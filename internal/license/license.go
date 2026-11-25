// Package license serves license requests for each DRM system. Every system
// goes through the same authorisation pipeline (authorize) and differs only in
// how it wraps the content keys it is allowed to release.
package license

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/opendrm-org/opendrm/internal/keystore"
	"github.com/opendrm-org/opendrm/internal/policy"
	"github.com/opendrm-org/opendrm/internal/session"
	"github.com/opendrm-org/opendrm/internal/token"
)

// Service holds everything the license endpoints need.
type Service struct {
	Keys        keystore.Store
	Policies    map[string]policy.Policy
	TokenSecret []byte
	// TokenLeeway absorbs clock skew between the operator's backend and opendrm.
	TokenLeeway time.Duration
	Streams     *session.Tracker
	Revoked     *session.Revocations
	// CountryHeader is set by the CDN or proxy in front of opendrm,
	// e.g. "CF-IPCountry" (Cloudflare) or "CloudFront-Viewer-Country".
	CountryHeader string
	// AllowedOrigins for browser players. "*" allows any origin.
	AllowedOrigins []string
	Now            func() time.Time
	Log            *slog.Logger
}

const maxBody = 64 << 10

// Handler returns the HTTP routes.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/license/clearkey", s.clearKey)
	mux.HandleFunc("GET /v1/hls-key/{kid}", s.hlsKey)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return s.cors(mux)
}

// denial is a refused request. Status is the HTTP status to send.
type denial struct {
	Status int
	Reason string
	Detail map[string]any
}

// grant is the outcome of a successful authorisation.
type grant struct {
	claims *token.Claims
	keys   []keystore.ContentKey
	// omitted counts hardware-only keys withheld from a software-only system.
	omitted int
}

// authorize runs the checks in the order the console's license log shows them.
// software is true for systems without hardware protection (ClearKey, HLS-AES).
func (s *Service) authorize(r *http.Request, kids []keystore.KeyID, software bool) (*grant, *denial) {
	now := s.Now()

	// 1. Token signature and expiry.
	claims, err := token.Verify(s.TokenSecret, bearer(r), now, s.TokenLeeway)
	if errors.Is(err, token.ErrExpired) {
		return nil, &denial{Status: http.StatusUnauthorized, Reason: policy.ReasonTokenExpired}
	}
	if err != nil {
		return nil, &denial{Status: http.StatusUnauthorized, Reason: policy.ReasonInvalidToken}
	}

	// Look up every requested key and the policies that govern them.
	keys := make([]keystore.ContentKey, 0, len(kids))
	var policies []policy.Policy
	seen := map[string]bool{}
	for _, kid := range kids {
		ck, err := s.Keys.Get(kid)
		if errors.Is(err, keystore.ErrNotFound) {
			return nil, &denial{Status: http.StatusNotFound, Reason: policy.ReasonUnknownKey, Detail: map[string]any{"kid": kid.String()}}
		}
		if err != nil {
			s.Log.Error("key lookup failed", "kid", kid.String(), "err", err)
			return nil, &denial{Status: http.StatusInternalServerError, Reason: "internal_error"}
		}
		if ck.Title != claims.Title {
			return nil, &denial{Status: http.StatusForbidden, Reason: policy.ReasonNotEntitled,
				Detail: map[string]any{"token_title": claims.Title, "key_title": ck.Title}}
		}
		if !seen[ck.Policy] {
			p, ok := s.Policies[ck.Policy]
			if !ok {
				s.Log.Error("key refers to unknown policy", "kid", kid.String(), "policy", ck.Policy)
				return nil, &denial{Status: http.StatusInternalServerError, Reason: "internal_error"}
			}
			seen[ck.Policy] = true
			policies = append(policies, p)
		}
		keys = append(keys, ck)
	}

	// 2. Token age, 3. entitlement.
	for _, p := range policies {
		if reason, detail := p.CheckTokenAge(claims.Age(now)); reason != "" {
			return nil, &denial{Status: http.StatusUnauthorized, Reason: reason, Detail: detail}
		}
		if reason, detail := p.CheckEntitlement(claims); reason != "" {
			return nil, &denial{Status: http.StatusForbidden, Reason: reason, Detail: detail}
		}
	}

	// 4. Device not revoked.
	device := claims.Device
	if device == "" {
		device = "default"
	}
	if s.Revoked.IsRevoked(claims.Subject, device, claims.IssuedAt) {
		return nil, &denial{Status: http.StatusForbidden, Reason: policy.ReasonDeviceRevoked}
	}

	// 5. Country.
	country := ""
	if s.CountryHeader != "" {
		country = strings.TrimSpace(r.Header.Get(s.CountryHeader))
	}
	for _, p := range policies {
		if reason, detail := p.CheckCountry(country); reason != "" {
			return nil, &denial{Status: http.StatusForbidden, Reason: reason, Detail: detail}
		}
	}

	// 6. Security level: software systems never receive hardware-only keys.
	g := &grant{claims: claims}
	for _, ck := range keys {
		if software && ck.RequiresHardware {
			g.omitted++
			continue
		}
		g.keys = append(g.keys, ck)
	}
	if len(g.keys) == 0 {
		return nil, &denial{Status: http.StatusForbidden, Reason: policy.ReasonSecurityLevel,
			Detail: map[string]any{"hardware_only_keys": g.omitted}}
	}

	// 7. Streams at once. Last, because a grant takes a slot.
	limit := 0
	for _, p := range policies {
		if p.MaxStreams > 0 && (limit == 0 || p.MaxStreams < limit) {
			limit = p.MaxStreams
		}
	}
	if ok, active := s.Streams.Acquire(claims.Subject, device, limit, now); !ok {
		return nil, &denial{Status: http.StatusForbidden, Reason: policy.ReasonConcurrency,
			Detail: map[string]any{"active": active, "limit": limit}}
	}
	return g, nil
}

// bearer reads the playback token from the Authorization header, or from the
// "token" query parameter for players that cannot set headers on key requests
// (AVPlayer fetching an HLS key URI).
func bearer(r *http.Request) string {
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return r.URL.Query().Get("token")
}

// clearKey implements the W3C EME ClearKey license exchange:
//
//	request:  {"kids": ["<base64url>"], "type": "temporary"}
//	response: {"keys": [{"kty": "oct", "kid": "<base64url>", "k": "<base64url>"}], "type": "temporary"}
//
// Hardware-only keys are left out of the response; the player then restricts
// itself to the renditions it has keys for.
func (s *Service) clearKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kids []string `json:"kids"`
		Type string   `json:"type"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&req); err != nil || len(req.Kids) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"granted": false, "reason": "bad_request",
			"message": "Expected a ClearKey license request with at least one key id."})
		return
	}
	kids := make([]keystore.KeyID, 0, len(req.Kids))
	for _, k := range req.Kids {
		kid, err := keystore.ParseKeyID(k)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"granted": false, "reason": "bad_request", "message": err.Error()})
			return
		}
		kids = append(kids, kid)
	}

	g, d := s.authorize(r, kids, true)
	if d != nil {
		s.deny(w, r, "clearkey", d)
		return
	}
	type jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		K   string `json:"k"`
	}
	resp := struct {
		Keys []jwk  `json:"keys"`
		Type string `json:"type"`
	}{Type: req.Type}
	if resp.Type == "" {
		resp.Type = "temporary"
	}
	for _, ck := range g.keys {
		resp.Keys = append(resp.Keys, jwk{Kty: "oct", Kid: ck.KID.Base64URL(), K: b64url(ck.Key[:])})
	}
	s.granted(r, "clearkey", g)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// hlsKey serves the raw 16-byte AES-128 key for an HLS EXT-X-KEY URI.
func (s *Service) hlsKey(w http.ResponseWriter, r *http.Request) {
	kid, err := keystore.ParseKeyID(r.PathValue("kid"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"granted": false, "reason": "bad_request", "message": err.Error()})
		return
	}
	g, d := s.authorize(r, []keystore.KeyID{kid}, true)
	if d != nil {
		s.deny(w, r, "hls-aes", d)
		return
	}
	s.granted(r, "hls-aes", g)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(g.keys[0].Key[:])
}

func (s *Service) deny(w http.ResponseWriter, r *http.Request, system string, d *denial) {
	msg := policy.Messages[d.Reason]
	if msg == "" {
		msg = "Something went wrong. Try again in a moment."
	}
	s.Log.Info("license", "system", system, "outcome", "denied", "reason", d.Reason, "detail", d.Detail, "remote", r.RemoteAddr)
	body := map[string]any{"granted": false, "reason": d.Reason, "message": msg}
	if d.Detail != nil {
		body["detail"] = d.Detail
	}
	writeJSON(w, d.Status, body)
}

func (s *Service) granted(r *http.Request, system string, g *grant) {
	s.Log.Info("license", "system", system, "outcome", "granted",
		"title", g.claims.Title, "viewer", g.claims.Subject, "device", g.claims.Device,
		"keys", len(g.keys), "hardware_keys_withheld", g.omitted, "remote", r.RemoteAddr)
}

func (s *Service) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && s.originAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) originAllowed(origin string) bool {
	for _, o := range s.AllowedOrigins {
		if o == "*" || strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
