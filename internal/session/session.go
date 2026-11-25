// Package session tracks who is streaming right now and which devices have
// been revoked.
//
// A stream is a lease: each granted license request for a (viewer, device)
// starts or renews it, and it lapses after the TTL without a renewal. Players
// renew licenses while playing, so an abandoned stream frees its slot on its own.
package session

import (
	"sort"
	"sync"
	"time"
)

// Tracker counts active streams per viewer. Safe for concurrent use.
// It is in memory, so it covers one opendrm instance; a shared backend
// (Redis or Postgres) can replace it for multi-instance deployments.
type Tracker struct {
	mu      sync.Mutex
	ttl     time.Duration
	streams map[string]map[string]time.Time // viewer -> device -> lease expiry
}

// NewTracker creates a tracker whose leases last ttl.
func NewTracker(ttl time.Duration) *Tracker {
	return &Tracker{ttl: ttl, streams: map[string]map[string]time.Time{}}
}

// Acquire starts or renews a stream for (viewer, device). If the viewer is
// already at limit on other devices it returns ok=false and leaves the leases
// untouched. active is the number of streams including this one.
// limit <= 0 means unlimited.
func (t *Tracker) Acquire(viewer, device string, limit int, now time.Time) (ok bool, active int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	devs := t.streams[viewer]
	if devs == nil {
		devs = map[string]time.Time{}
		t.streams[viewer] = devs
	}
	for d, exp := range devs {
		if !now.Before(exp) {
			delete(devs, d)
		}
	}
	if _, renewing := devs[device]; !renewing && limit > 0 && len(devs) >= limit {
		return false, len(devs) + 1
	}
	devs[device] = now.Add(t.ttl)
	return true, len(devs)
}

// Release ends a stream immediately (for example when a viewer presses
// "stop" on another device).
func (t *Tracker) Release(viewer, device string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.streams[viewer], device)
}

// Active lists a viewer's devices with live leases, sorted.
func (t *Tracker) Active(viewer string, now time.Time) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for d, exp := range t.streams[viewer] {
		if now.Before(exp) {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// Revocations is the set of devices an admin has signed out.
type Revocations struct {
	mu      sync.RWMutex
	devices map[string]map[string]bool // viewer -> device
	all     map[string]time.Time       // viewer -> "sign out everywhere" time
}

func NewRevocations() *Revocations {
	return &Revocations{devices: map[string]map[string]bool{}, all: map[string]time.Time{}}
}

// Revoke signs one device out.
func (r *Revocations) Revoke(viewer, device string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.devices[viewer] == nil {
		r.devices[viewer] = map[string]bool{}
	}
	r.devices[viewer][device] = true
}

// RevokeAll signs out every device for viewer whose token was issued before at.
// Tokens issued afterwards (the viewer signed in again) are accepted.
func (r *Revocations) RevokeAll(viewer string, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.all[viewer] = at
}

// IsRevoked reports whether a token for (viewer, device), issued at issuedAt, is revoked.
func (r *Revocations) IsRevoked(viewer, device string, issuedAt time.Time) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.devices[viewer][device] {
		return true
	}
	if at, ok := r.all[viewer]; ok && !issuedAt.After(at) {
		return true
	}
	return false
}
