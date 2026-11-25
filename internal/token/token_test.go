package token

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

var secret = []byte("test-secret")

func mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok, err := Sign(secret, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestVerifyValid(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tok := mint(t, map[string]any{"sub": "user_8812", "title": "ip-c3", "device": "pixel8", "plan": "paid", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()})
	c, err := Verify(secret, tok, now, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user_8812" || c.Title != "ip-c3" || c.Device != "pixel8" || c.String("plan") != "paid" {
		t.Fatalf("claims = %+v", c)
	}
}

func TestVerifyRejects(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	good := map[string]any{"sub": "u", "title": "t", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}

	t.Run("wrong secret", func(t *testing.T) {
		tok := mint(t, good)
		if _, err := Verify([]byte("other"), tok, now, 0); !errors.Is(err, ErrSignature) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		tok := mint(t, good)
		parts := strings.Split(tok, ".")
		evil := mint(t, map[string]any{"sub": "admin", "title": "t", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
		parts[1] = strings.Split(evil, ".")[1]
		if _, err := Verify(secret, strings.Join(parts, "."), now, 0); !errors.Is(err, ErrSignature) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("alg none", func(t *testing.T) {
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		p := strings.Split(mint(t, good), ".")[1]
		if _, err := Verify(secret, h+"."+p+".", now, 0); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		tok := mint(t, good)
		if _, err := Verify(secret, tok, now.Add(2*time.Minute), 5*time.Second); !errors.Is(err, ErrExpired) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("issued in future", func(t *testing.T) {
		tok := mint(t, map[string]any{"sub": "u", "title": "t", "iat": now.Add(time.Hour).Unix(), "exp": now.Add(2 * time.Hour).Unix()})
		if _, err := Verify(secret, tok, now, 5*time.Second); !errors.Is(err, ErrNotYet) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing claims", func(t *testing.T) {
		tok := mint(t, map[string]any{"sub": "u", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix()})
		if _, err := Verify(secret, tok, now, 0); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		if _, err := Verify(secret, "not-a-token", now, 0); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no secret configured", func(t *testing.T) {
		if _, err := Verify(nil, mint(t, good), now, 0); err == nil {
			t.Fatal("expected error with empty secret")
		}
	})
}

func TestStringClaimTypes(t *testing.T) {
	c := &Claims{Raw: map[string]any{"n": float64(3), "b": true, "f": 1.5}}
	if c.String("n") != "3" || c.String("b") != "true" || c.String("f") != "1.5" || c.String("missing") != "" {
		t.Fatalf("got %q %q %q", c.String("n"), c.String("b"), c.String("f"))
	}
}
