package session

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestStreamLimit(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tr := NewTracker(10 * time.Minute)

	if ok, n := tr.Acquire("u", "android", 2, now); !ok || n != 1 {
		t.Fatalf("1st: ok=%v n=%d", ok, n)
	}
	if ok, n := tr.Acquire("u", "web", 2, now); !ok || n != 2 {
		t.Fatalf("2nd: ok=%v n=%d", ok, n)
	}
	if ok, n := tr.Acquire("u", "ipad", 2, now); ok || n != 3 {
		t.Fatalf("3rd should be denied: ok=%v n=%d", ok, n)
	}
	// Renewing an existing stream is always allowed.
	if ok, _ := tr.Acquire("u", "web", 2, now.Add(time.Minute)); !ok {
		t.Fatal("renewal denied")
	}
	// Another viewer is unaffected.
	if ok, _ := tr.Acquire("v", "ipad", 2, now); !ok {
		t.Fatal("other viewer denied")
	}
	if got := tr.Active("u", now); !reflect.DeepEqual(got, []string{"android", "web"}) {
		t.Fatalf("active = %v", got)
	}
}

func TestLeasesExpire(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tr := NewTracker(10 * time.Minute)
	tr.Acquire("u", "a", 1, now)
	if ok, _ := tr.Acquire("u", "b", 1, now.Add(9*time.Minute)); ok {
		t.Fatal("second device allowed while first lease is live")
	}
	if ok, _ := tr.Acquire("u", "b", 1, now.Add(10*time.Minute)); !ok {
		t.Fatal("second device denied after first lease expired")
	}
}

func TestReleaseFreesSlot(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tr := NewTracker(time.Hour)
	tr.Acquire("u", "a", 1, now)
	tr.Release("u", "a")
	if ok, _ := tr.Acquire("u", "b", 1, now); !ok {
		t.Fatal("slot not freed by Release")
	}
}

func TestUnlimited(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tr := NewTracker(time.Hour)
	for i := 0; i < 50; i++ {
		if ok, _ := tr.Acquire("u", string(rune('a'+i)), 0, now); !ok {
			t.Fatal("unlimited policy denied a stream")
		}
	}
}

func TestConcurrentAcquireNeverExceedsLimit(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tr := NewTracker(time.Hour)
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if ok, _ := tr.Acquire("u", string(rune(1000+i)), 2, now); ok {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if granted != 2 {
		t.Fatalf("granted %d streams, limit 2", granted)
	}
}

func TestRevocations(t *testing.T) {
	r := NewRevocations()
	t0 := time.Unix(1_800_000_000, 0)
	r.Revoke("u", "galaxy-tab")
	if !r.IsRevoked("u", "galaxy-tab", t0) || r.IsRevoked("u", "pixel", t0) || r.IsRevoked("v", "galaxy-tab", t0) {
		t.Fatal("single-device revocation wrong")
	}
	r.RevokeAll("u", t0)
	if !r.IsRevoked("u", "pixel", t0.Add(-time.Second)) {
		t.Fatal("token issued before sign-out-everywhere accepted")
	}
	if r.IsRevoked("u", "pixel", t0.Add(time.Second)) {
		t.Fatal("token issued after signing in again rejected")
	}
}
