// Package token verifies playback tokens: HS256 JWTs that the operator's
// backend signs with a secret it shares with opendrm. A token says who the
// viewer is, which title they may play, and anything the policy needs
// (for example plan=paid).
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

var (
	ErrMalformed = errors.New("malformed token")
	ErrSignature = errors.New("bad token signature")
	ErrExpired   = errors.New("token expired")
	ErrNotYet    = errors.New("token issued in the future")
)

// Claims are the verified contents of a playback token.
type Claims struct {
	Subject   string // sub: the viewer's account id
	Title     string // title: the title id the viewer may play
	Device    string // device: a stable id for this device or app install
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Raw holds every claim, so policies can match custom ones like "plan".
	Raw map[string]any
}

// String returns a custom claim as a string, or "" if absent.
func (c *Claims) String(name string) string {
	switch v := c.Raw[name].(type) {
	case string:
		return v
	case float64:
		if v == math.Trunc(v) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%g", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	}
	return ""
}

// Age is how long ago the token was issued.
func (c *Claims) Age(now time.Time) time.Duration { return now.Sub(c.IssuedAt) }

var b64 = base64.RawURLEncoding

// Verify checks the signature and time claims. leeway absorbs small clock
// differences between the operator's backend and opendrm.
func Verify(secret []byte, tok string, now time.Time, leeway time.Duration) (*Claims, error) {
	if len(secret) == 0 {
		return nil, errors.New("token secret is not configured")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	var header struct {
		Alg string `json:"alg"`
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil {
		return nil, ErrMalformed
	}
	// Only HS256 is accepted. Never trust "alg": "none" or a downgraded alg.
	if header.Alg != "HS256" {
		return nil, ErrMalformed
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, ErrSignature
	}

	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	raw := map[string]any{}
	if err := json.Unmarshal(pb, &raw); err != nil {
		return nil, ErrMalformed
	}
	c := &Claims{Raw: raw}
	c.Subject, _ = raw["sub"].(string)
	c.Title, _ = raw["title"].(string)
	c.Device, _ = raw["device"].(string)
	exp, okExp := raw["exp"].(float64)
	iat, okIat := raw["iat"].(float64)
	if !okExp || !okIat || c.Subject == "" || c.Title == "" {
		return nil, ErrMalformed
	}
	c.ExpiresAt = time.Unix(int64(exp), 0)
	c.IssuedAt = time.Unix(int64(iat), 0)

	if now.After(c.ExpiresAt.Add(leeway)) {
		return c, ErrExpired
	}
	if c.IssuedAt.After(now.Add(leeway)) {
		return c, ErrNotYet
	}
	return c, nil
}

// Sign creates a token. opendrm uses it for the CLI's test tokens; operators
// normally sign with an SDK in their own backend.
func Sign(secret []byte, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signing))
	return signing + "." + b64.EncodeToString(mac.Sum(nil)), nil
}
