package keystore

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned when no content key exists for a KID.
var ErrNotFound = errors.New("content key not found")

// KeyID is a 16-byte content key identifier (the KID in CENC and EME).
type KeyID [16]byte

// String formats the KID as a UUID, the form used in manifests and the console.
func (k KeyID) String() string {
	h := hex.EncodeToString(k[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// Base64URL is the unpadded base64url form that ClearKey (W3C EME) uses.
func (k KeyID) Base64URL() string { return base64.RawURLEncoding.EncodeToString(k[:]) }

// ParseKeyID accepts a UUID, 32 hex characters, or unpadded/padded base64url.
func ParseKeyID(s string) (KeyID, error) {
	var kid KeyID
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) == 32 {
		if b, err := hex.DecodeString(clean); err == nil {
			copy(kid[:], b)
			return kid, nil
		}
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(s), "="))
	if err != nil || len(b) != 16 {
		return kid, fmt.Errorf("invalid key id %q", s)
	}
	copy(kid[:], b)
	return kid, nil
}

// ContentKey is one AES-128 key used to encrypt one or more tracks of a title.
type ContentKey struct {
	KID   KeyID
	Key   [16]byte
	Title string
	Track string
	// Policy names the policy that decides who may receive this key.
	Policy string
	// RequiresHardware keys are only released to hardware-backed DRM
	// (Widevine L1, FairPlay), never to ClearKey or HLS-AES.
	RequiresHardware bool
	CreatedAt        time.Time
}

// Store persists content keys.
type Store interface {
	Put(ContentKey) error
	Get(KeyID) (ContentKey, error)
	List() ([]ContentKey, error)
}

// record is the on-disk form. The key itself is only ever stored wrapped.
type record struct {
	KID              string    `json:"kid"`
	WrappedKey       string    `json:"wrapped_key"`
	MasterKeyID      string    `json:"master_key_id"`
	Title            string    `json:"title"`
	Track            string    `json:"track"`
	Policy           string    `json:"policy"`
	RequiresHardware bool      `json:"requires_hardware,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// FileStore keeps wrapped keys in a single JSON file. Fine for thousands of
// titles; a SQL-backed store can implement the same interface later.
type FileStore struct {
	mu   sync.RWMutex
	path string
	mk   MasterKey
	recs map[KeyID]record
}

// OpenFileStore loads path if it exists, otherwise starts empty.
func OpenFileStore(path string, mk MasterKey) (*FileStore, error) {
	fs := &FileStore{path: path, mk: mk, recs: map[KeyID]record{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fs, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []record
	if err := json.Unmarshal(raw, &recs); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	for _, r := range recs {
		kid, err := ParseKeyID(r.KID)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		fs.recs[kid] = r
	}
	return fs, nil
}

// Generate creates a random content key, stores it and returns it.
func (fs *FileStore) Generate(title, track, policy string, requiresHardware bool) (ContentKey, error) {
	ck := ContentKey{
		Title:            title,
		Track:            track,
		Policy:           policy,
		RequiresHardware: requiresHardware,
		CreatedAt:        time.Now().UTC().Truncate(time.Second),
	}
	if _, err := rand.Read(ck.KID[:]); err != nil {
		return ck, err
	}
	if _, err := rand.Read(ck.Key[:]); err != nil {
		return ck, err
	}
	return ck, fs.Put(ck)
}

func (fs *FileStore) Put(ck ContentKey) error {
	wrapped, err := fs.mk.Wrap(ck.Key[:], ck.KID[:])
	if err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.recs[ck.KID] = record{
		KID:              ck.KID.String(),
		WrappedKey:       base64.StdEncoding.EncodeToString(wrapped),
		MasterKeyID:      fs.mk.ID(),
		Title:            ck.Title,
		Track:            ck.Track,
		Policy:           ck.Policy,
		RequiresHardware: ck.RequiresHardware,
		CreatedAt:        ck.CreatedAt,
	}
	return fs.saveLocked()
}

func (fs *FileStore) Get(kid KeyID) (ContentKey, error) {
	fs.mu.RLock()
	r, ok := fs.recs[kid]
	fs.mu.RUnlock()
	if !ok {
		return ContentKey{}, ErrNotFound
	}
	return fs.unwrap(kid, r)
}

func (fs *FileStore) List() ([]ContentKey, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	out := make([]ContentKey, 0, len(fs.recs))
	for kid, r := range fs.recs {
		ck, err := fs.unwrap(kid, r)
		if err != nil {
			return nil, err
		}
		out = append(out, ck)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].KID.String() < out[j].KID.String()
	})
	return out, nil
}

func (fs *FileStore) unwrap(kid KeyID, r record) (ContentKey, error) {
	if r.MasterKeyID != fs.mk.ID() {
		return ContentKey{}, fmt.Errorf("key %s was wrapped by master key %s, loaded %s", kid, r.MasterKeyID, fs.mk.ID())
	}
	wrapped, err := base64.StdEncoding.DecodeString(r.WrappedKey)
	if err != nil {
		return ContentKey{}, err
	}
	plain, err := fs.mk.Unwrap(wrapped, kid[:])
	if err != nil {
		return ContentKey{}, fmt.Errorf("unwrap key %s: %w", kid, err)
	}
	ck := ContentKey{
		KID:              kid,
		Title:            r.Title,
		Track:            r.Track,
		Policy:           r.Policy,
		RequiresHardware: r.RequiresHardware,
		CreatedAt:        r.CreatedAt,
	}
	copy(ck.Key[:], plain)
	return ck, nil
}

// saveLocked writes the whole file atomically: temp file, fsync, rename.
func (fs *FileStore) saveLocked() error {
	recs := make([]record, 0, len(fs.recs))
	for _, r := range fs.recs {
		recs = append(recs, r)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].KID < recs[j].KID })
	raw, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(fs.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(fs.path), ".keys-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), fs.path)
}
