package policy

import (
	"testing"
	"time"
)

type claims map[string]string

func (c claims) String(name string) string { return c[name] }

func TestEntitlement(t *testing.T) {
	p := Policy{RequireClaims: map[string]string{"plan": "paid"}}
	if r, _ := p.CheckEntitlement(claims{"plan": "paid"}); r != "" {
		t.Fatalf("paid viewer denied: %s", r)
	}
	if r, d := p.CheckEntitlement(claims{"plan": "free"}); r != ReasonNotEntitled || d["got"] != "free" {
		t.Fatalf("free viewer: %s %v", r, d)
	}
	if r, _ := p.CheckEntitlement(claims{}); r != ReasonNotEntitled {
		t.Fatalf("missing claim: %s", r)
	}
	if r, _ := (Policy{}).CheckEntitlement(claims{}); r != "" {
		t.Fatalf("policy with no requirements denied: %s", r)
	}
}

func TestTokenAge(t *testing.T) {
	p := Policy{MaxTokenAge: 60}
	if r, _ := p.CheckTokenAge(59 * time.Second); r != "" {
		t.Fatal("fresh token denied")
	}
	if r, _ := p.CheckTokenAge(61 * time.Second); r != ReasonTokenExpired {
		t.Fatal("old token allowed")
	}
	if r, _ := (Policy{}).CheckTokenAge(time.Hour); r != "" {
		t.Fatal("no max age should allow any age")
	}
}

func TestCountry(t *testing.T) {
	p := Policy{BlockedCountries: []string{"AE", "sa"}}
	if r, d := p.CheckCountry("ae"); r != ReasonGeoBlocked || d["country"] != "AE" {
		t.Fatalf("AE: %s %v", r, d)
	}
	if r, _ := p.CheckCountry("SA"); r != ReasonGeoBlocked {
		t.Fatal("SA allowed")
	}
	if r, _ := p.CheckCountry("IN"); r != "" {
		t.Fatal("IN blocked")
	}
	if r, _ := p.CheckCountry(""); r != "" {
		t.Fatal("unknown country blocked")
	}
}

func TestEveryReasonHasAMessage(t *testing.T) {
	for _, r := range []string{ReasonInvalidToken, ReasonTokenExpired, ReasonNotEntitled, ReasonDeviceRevoked, ReasonGeoBlocked, ReasonSecurityLevel, ReasonConcurrency, ReasonUnknownKey} {
		if Messages[r] == "" {
			t.Errorf("no viewer message for %s", r)
		}
	}
}
