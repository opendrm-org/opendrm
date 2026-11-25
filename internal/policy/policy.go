// Package policy decides whether a viewer may receive a title's keys.
package policy

import (
	"strings"
	"time"
)

// Reason codes. They appear in API responses, the license log and the
// console, and each one maps to a message the player shows the viewer.
const (
	ReasonInvalidToken  = "invalid_token"
	ReasonTokenExpired  = "token_expired"
	ReasonNotEntitled   = "not_entitled"
	ReasonDeviceRevoked = "device_revoked"
	ReasonGeoBlocked    = "geo_blocked"
	ReasonSecurityLevel = "security_level"
	ReasonConcurrency   = "concurrency"
	ReasonUnknownKey    = "unknown_key"
)

// Messages are written for viewers, not operators. Players may show them as is.
var Messages = map[string]string{
	ReasonInvalidToken:  "We couldn't confirm your account. Sign in again to watch.",
	ReasonTokenExpired:  "Your session timed out. Press play again.",
	ReasonNotEntitled:   "Your plan doesn't include this title.",
	ReasonDeviceRevoked: "This device was signed out. Sign in again to watch here.",
	ReasonGeoBlocked:    "This title isn't available in your country.",
	ReasonSecurityLevel: "This device can't play this quality securely.",
	ReasonConcurrency:   "You're watching on too many devices. Stop one to watch here.",
	ReasonUnknownKey:    "This title isn't ready to play yet.",
}

// Seconds is a duration written as a whole number of seconds in JSON config.
type Seconds int

func (s Seconds) Duration() time.Duration { return time.Duration(s) * time.Second }

// Policy is a named set of rules attached to content keys.
type Policy struct {
	Name string `json:"name"`
	// RequireClaims must all be present in the token with these exact values,
	// for example {"plan": "paid"}.
	RequireClaims map[string]string `json:"require_claims,omitempty"`
	// MaxTokenAge rejects tokens issued longer ago than this. 0 means only
	// the token's own exp applies.
	MaxTokenAge Seconds `json:"max_token_age,omitempty"`
	// MaxStreams is how many devices one account may stream on at once. 0 = no limit.
	MaxStreams int `json:"max_streams,omitempty"`
	// BlockedCountries are ISO 3166-1 alpha-2 codes.
	BlockedCountries []string `json:"blocked_countries,omitempty"`
}

// Claim is the subset of a playback token a policy looks at.
type Claim interface {
	String(name string) string
}

// CheckEntitlement returns ReasonNotEntitled if a required claim is missing or different.
func (p Policy) CheckEntitlement(c Claim) (reason string, detail map[string]any) {
	for name, want := range p.RequireClaims {
		if got := c.String(name); got != want {
			return ReasonNotEntitled, map[string]any{"claim": name, "want": want, "got": got}
		}
	}
	return "", nil
}

// CheckTokenAge returns ReasonTokenExpired if the token is older than MaxTokenAge.
func (p Policy) CheckTokenAge(age time.Duration) (reason string, detail map[string]any) {
	if p.MaxTokenAge > 0 && age > p.MaxTokenAge.Duration() {
		return ReasonTokenExpired, map[string]any{"age_seconds": int(age.Seconds()), "max_seconds": int(p.MaxTokenAge)}
	}
	return "", nil
}

// CheckCountry returns ReasonGeoBlocked if country is blocked. An unknown
// country ("") is allowed, so a missing CDN header never locks everyone out.
func (p Policy) CheckCountry(country string) (reason string, detail map[string]any) {
	for _, blocked := range p.BlockedCountries {
		if country != "" && strings.EqualFold(blocked, country) {
			return ReasonGeoBlocked, map[string]any{"country": strings.ToUpper(country)}
		}
	}
	return "", nil
}
