// Package keystore holds content keys. Every content key is wrapped with a
// master key before it is written anywhere, so a copy of the key file alone
// is useless without the master key.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MasterKey wraps and unwraps content keys. Implementations can live in a
// local file (LocalMasterKey) or, later, in a KMS such as AWS KMS or Vault.
type MasterKey interface {
	// ID identifies the master key so wrapped keys can record which one was used.
	ID() string
	Wrap(plaintext, aad []byte) ([]byte, error)
	Unwrap(wrapped, aad []byte) ([]byte, error)
}

// LocalMasterKey is an AES-256-GCM key held in memory, loaded from a file.
type LocalMasterKey struct {
	aead cipher.AEAD
	id   string
}

// NewLocalMasterKey builds a master key from 32 raw bytes.
func NewLocalMasterKey(key []byte) (*LocalMasterKey, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(key)
	return &LocalMasterKey{aead: aead, id: "local:" + hex.EncodeToString(sum[:4])}, nil
}

// LoadOrCreateLocalMasterKey reads a hex-encoded 32-byte key from path. If the
// file does not exist it creates one with mode 0600. created reports whether a
// new key was generated.
func LoadOrCreateLocalMasterKey(path string) (mk *LocalMasterKey, created bool, err error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, false, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, false, err
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
			return nil, false, err
		}
		mk, err := NewLocalMasterKey(key)
		return mk, true, err
	}
	if err != nil {
		return nil, false, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, false, fmt.Errorf("master key file %s is not hex: %w", path, err)
	}
	mk, err = NewLocalMasterKey(key)
	return mk, false, err
}

func (m *LocalMasterKey) ID() string { return m.id }

// Wrap returns nonce || ciphertext. aad binds the result to its context
// (the content key's KID), so a wrapped key cannot be swapped onto another KID.
func (m *LocalMasterKey) Wrap(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return m.aead.Seal(nonce, nonce, plaintext, aad), nil
}

func (m *LocalMasterKey) Unwrap(wrapped, aad []byte) ([]byte, error) {
	n := m.aead.NonceSize()
	if len(wrapped) < n {
		return nil, errors.New("wrapped key too short")
	}
	return m.aead.Open(nil, wrapped[:n], wrapped[n:], aad)
}
