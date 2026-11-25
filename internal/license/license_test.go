package license

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opendrm-org/opendrm/internal/keystore"
	"github.com/opendrm-org/opendrm/internal/policy"
	"github.com/opendrm-org/opendrm/internal/session"
	"github.com/opendrm-org/opendrm/internal/token"
)

var secret = []byte("shared-with-backend")

type fixture struct {
	svc    *Service
	srv    *httptest.Server
	now    time.Time
	sd, hd keystore.ContentKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	mk, _ := keystore.NewLocalMasterKey(bytes.Repeat([]byte{1}, 32))
	store, err := keystore.OpenFileStore(filepath.Join(t.TempDir(), "keys.json"), mk)
	if err != nil {
		t.Fatal(err)
	}
	sd, _ := store.Generate("ip-c3", "sd+720p", "paid-members", false)
	hd, _ := store.Generate("ip-c3", "1080p", "paid-members", true)

	f := &fixture{now: time.Unix(1_800_000_000, 0), sd: sd, hd: hd}
	f.svc = &Service{
		Keys: store,
		Policies: map[string]policy.Policy{"paid-members": {
			Name:             "paid-members",
			RequireClaims:    map[string]string{"plan": "paid"},
			MaxTokenAge:      120,
			MaxStreams:       2,
			BlockedCountries: []string{"AE"},
		}},
		TokenSecret:    secret,
		TokenLeeway:    5 * time.Second,
		Streams:        session.NewTracker(10 * time.Minute),
		Revoked:        session.NewRevocations(),
		CountryHeader:  "CF-IPCountry",
		AllowedOrigins: []string{"https://app.happythoughts.in"},
		Now:            func() time.Time { return f.now },
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	f.srv = httptest.NewServer(f.svc.Handler())
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) token(t *testing.T, over map[string]any) string {
	t.Helper()
	c := map[string]any{"sub": "user_8812", "title": "ip-c3", "device": "pixel8", "plan": "paid",
		"iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix()}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	tok, err := token.Sign(secret, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type licenseResp struct {
	Granted *bool          `json:"granted"`
	Reason  string         `json:"reason"`
	Message string         `json:"message"`
	Detail  map[string]any `json:"detail"`
	Keys    []struct {
		Kty, Kid, K string
	} `json:"keys"`
	Type string `json:"type"`
}

func (f *fixture) clearKey(t *testing.T, tok string, headers map[string]string, kids ...keystore.KeyID) (int, licenseResp) {
	t.Helper()
	var ids []string
	for _, k := range kids {
		ids = append(ids, k.Base64URL())
	}
	body, _ := json.Marshal(map[string]any{"kids": ids, "type": "temporary"})
	req, _ := http.NewRequest("POST", f.srv.URL+"/v1/license/clearkey", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out licenseResp
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestClearKeyGrantsSoftwareKeysOnly(t *testing.T) {
	f := newFixture(t)
	status, resp := f.clearKey(t, f.token(t, nil), nil, f.sd.KID, f.hd.KID)
	if status != 200 {
		t.Fatalf("status %d: %+v", status, resp)
	}
	if len(resp.Keys) != 1 {
		t.Fatalf("got %d keys, want only the SD key (1080p is hardware-only)", len(resp.Keys))
	}
	k := resp.Keys[0]
	if k.Kty != "oct" || k.Kid != f.sd.KID.Base64URL() || k.K != base64.RawURLEncoding.EncodeToString(f.sd.Key[:]) || resp.Type != "temporary" {
		t.Fatalf("bad ClearKey response: %+v", resp)
	}
}

func TestDenials(t *testing.T) {
	cases := []struct {
		name    string
		token   func(f *fixture, t *testing.T) string
		headers map[string]string
		setup   func(f *fixture)
		kids    func(f *fixture) []keystore.KeyID
		status  int
		reason  string
	}{
		{name: "no token", token: func(*fixture, *testing.T) string { return "" }, status: 401, reason: "invalid_token"},
		{name: "forged token", token: func(f *fixture, t *testing.T) string {
			tok, _ := token.Sign([]byte("wrong"), map[string]any{"sub": "u", "title": "ip-c3", "iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix()})
			return tok
		}, status: 401, reason: "invalid_token"},
		{name: "expired token", token: func(f *fixture, t *testing.T) string {
			return f.token(t, map[string]any{"exp": f.now.Add(-time.Minute).Unix()})
		}, status: 401, reason: "token_expired"},
		{name: "token too old for policy", token: func(f *fixture, t *testing.T) string {
			return f.token(t, map[string]any{"iat": f.now.Add(-5 * time.Minute).Unix(), "exp": f.now.Add(time.Hour).Unix()})
		}, status: 401, reason: "token_expired"},
		{name: "free plan", token: func(f *fixture, t *testing.T) string {
			return f.token(t, map[string]any{"plan": "free"})
		}, status: 403, reason: "not_entitled"},
		{name: "token for another title", token: func(f *fixture, t *testing.T) string {
			return f.token(t, map[string]any{"title": "other-title"})
		}, status: 403, reason: "not_entitled"},
		{name: "revoked device", setup: func(f *fixture) { f.svc.Revoked.Revoke("user_8812", "pixel8") }, status: 403, reason: "device_revoked"},
		{name: "blocked country", headers: map[string]string{"CF-IPCountry": "AE"}, status: 403, reason: "geo_blocked"},
		{name: "only hardware keys requested", kids: func(f *fixture) []keystore.KeyID { return []keystore.KeyID{f.hd.KID} }, status: 403, reason: "security_level"},
		{name: "unknown key", kids: func(f *fixture) []keystore.KeyID { return []keystore.KeyID{{0xde, 0xad}} }, status: 404, reason: "unknown_key"},
		{name: "third device", setup: func(f *fixture) {
			f.svc.Streams.Acquire("user_8812", "web", 2, f.now)
			f.svc.Streams.Acquire("user_8812", "ipad", 2, f.now)
		}, status: 403, reason: "concurrency"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.setup != nil {
				tc.setup(f)
			}
			tok := f.token(t, nil)
			if tc.token != nil {
				tok = tc.token(f, t)
			}
			kids := []keystore.KeyID{f.sd.KID}
			if tc.kids != nil {
				kids = tc.kids(f)
			}
			status, resp := f.clearKey(t, tok, tc.headers, kids...)
			if status != tc.status || resp.Reason != tc.reason {
				t.Fatalf("got %d %q, want %d %q (%+v)", status, resp.Reason, tc.status, tc.reason, resp)
			}
			if resp.Granted == nil || *resp.Granted || resp.Message == "" || len(resp.Keys) != 0 {
				t.Fatalf("denial body malformed: %+v", resp)
			}
		})
	}
}

func TestDeniedRequestsDoNotUseAStreamSlot(t *testing.T) {
	f := newFixture(t)
	// A viewer in a blocked country is denied before the stream check...
	f.clearKey(t, f.token(t, map[string]any{"device": "a"}), map[string]string{"CF-IPCountry": "AE"}, f.sd.KID)
	f.clearKey(t, f.token(t, map[string]any{"device": "b"}), map[string]string{"CF-IPCountry": "AE"}, f.sd.KID)
	// ...so two later plays from allowed countries still fit in the limit of 2.
	for _, dev := range []string{"c", "d"} {
		if status, resp := f.clearKey(t, f.token(t, map[string]any{"device": dev}), nil, f.sd.KID); status != 200 {
			t.Fatalf("device %s: %d %+v", dev, status, resp)
		}
	}
}

func TestStreamLimitAndRenewal(t *testing.T) {
	f := newFixture(t)
	for _, dev := range []string{"android", "web"} {
		if status, _ := f.clearKey(t, f.token(t, map[string]any{"device": dev}), nil, f.sd.KID); status != 200 {
			t.Fatalf("%s denied", dev)
		}
	}
	status, resp := f.clearKey(t, f.token(t, map[string]any{"device": "ipad"}), nil, f.sd.KID)
	if status != 403 || resp.Reason != "concurrency" || resp.Detail["active"].(float64) != 3 || resp.Detail["limit"].(float64) != 2 {
		t.Fatalf("third device: %d %+v", status, resp)
	}
	// The license renewal from a device already streaming is still granted.
	if status, _ := f.clearKey(t, f.token(t, map[string]any{"device": "web"}), nil, f.sd.KID); status != 200 {
		t.Fatal("renewal denied")
	}
}

func TestHLSKey(t *testing.T) {
	f := newFixture(t)

	get := func(path string, header string) (*http.Response, []byte) {
		req, _ := http.NewRequest("GET", f.srv.URL+path, nil)
		if header != "" {
			req.Header.Set("Authorization", "Bearer "+header)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res, b
	}

	// Token in the query string (AVPlayer cannot add headers to key URIs).
	res, body := get("/v1/hls-key/"+f.sd.KID.String()+"?token="+f.token(t, nil), "")
	if res.StatusCode != 200 || !bytes.Equal(body, f.sd.Key[:]) || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("query token: %d %x %v", res.StatusCode, body, res.Header)
	}
	// Token in the header.
	res, body = get("/v1/hls-key/"+f.sd.KID.String(), f.token(t, nil))
	if res.StatusCode != 200 || !bytes.Equal(body, f.sd.Key[:]) {
		t.Fatalf("header token: %d", res.StatusCode)
	}
	// Hardware-only keys are never served over HLS-AES.
	res, body = get("/v1/hls-key/"+f.hd.KID.String(), f.token(t, nil))
	if res.StatusCode != 403 || !strings.Contains(string(body), "security_level") {
		t.Fatalf("hd key over hls-aes: %d %s", res.StatusCode, body)
	}
	// Bad kid.
	if res, _ := get("/v1/hls-key/not-a-kid", f.token(t, nil)); res.StatusCode != 400 {
		t.Fatalf("bad kid: %d", res.StatusCode)
	}
}

func TestBadClearKeyRequests(t *testing.T) {
	f := newFixture(t)
	for _, body := range []string{"", "{}", `{"kids":[]}`, `{"kids":["!!"]}`, "not json"} {
		req, _ := http.NewRequest("POST", f.srv.URL+"/v1/license/clearkey", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+f.token(t, nil))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 400 {
			t.Errorf("body %q: status %d, want 400", body, res.StatusCode)
		}
	}
}

func TestCORS(t *testing.T) {
	f := newFixture(t)
	req, _ := http.NewRequest("OPTIONS", f.srv.URL+"/v1/license/clearkey", nil)
	req.Header.Set("Origin", "https://app.happythoughts.in")
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != 204 || res.Header.Get("Access-Control-Allow-Origin") != "https://app.happythoughts.in" ||
		!strings.Contains(res.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight: %d %v", res.StatusCode, res.Header)
	}
	req.Header.Set("Origin", "https://evil.example")
	res, _ = http.DefaultClient.Do(req)
	res.Body.Close()
	if res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unknown origin allowed")
	}
}

func TestHealthz(t *testing.T) {
	f := newFixture(t)
	res, err := http.Get(f.srv.URL + "/healthz")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", err, res)
	}
	res.Body.Close()
}
