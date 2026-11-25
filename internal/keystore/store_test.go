package keystore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testMaster(t *testing.T) *LocalMasterKey {
	t.Helper()
	mk, err := NewLocalMasterKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return mk
}

func TestParseKeyIDForms(t *testing.T) {
	want := KeyID{0x9e, 0xb4, 0x05, 0x0d, 0xe4, 0x4b, 0x48, 0x02, 0x93, 0x2e, 0x27, 0xd7, 0x50, 0x83, 0xe2, 0x66}
	for _, in := range []string{
		"9eb4050d-e44b-4802-932e-27d75083e266",
		"9eb4050de44b4802932e27d75083e266",
		want.Base64URL(),
		want.Base64URL() + "==",
	} {
		got, err := ParseKeyID(in)
		if err != nil {
			t.Fatalf("ParseKeyID(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseKeyID(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := ParseKeyID("nope"); err == nil {
		t.Fatal("expected error for invalid kid")
	}
}

func TestFileStoreRoundTripAndPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	mk := testMaster(t)

	fs, err := OpenFileStore(path, mk)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := fs.Generate("ip-c3", "1080p", "paid-members", true)
	if err != nil {
		t.Fatal(err)
	}

	// The plaintext key must never appear in the file.
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, ck.Key[:]) || strings.Contains(string(raw), fmtHex(ck.Key[:])) {
		t.Fatal("plaintext content key found in key file")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", info.Mode().Perm())
	}

	reopened, err := OpenFileStore(path, mk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Get(ck.KID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != ck.Key || got.Title != "ip-c3" || got.Track != "1080p" || !got.RequiresHardware || got.Policy != "paid-members" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	list, err := reopened.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %v, %v", list, err)
	}
}

func TestWrongMasterKeyCannotUnwrap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	fs, _ := OpenFileStore(path, testMaster(t))
	ck, err := fs.Generate("t", "sd", "p", false)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := NewLocalMasterKey(bytes.Repeat([]byte{9}, 32))
	fs2, err := OpenFileStore(path, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs2.Get(ck.KID); err == nil {
		t.Fatal("expected error unwrapping with the wrong master key")
	}
}

func TestWrappedKeyIsBoundToItsKID(t *testing.T) {
	mk := testMaster(t)
	var kidA, kidB KeyID
	kidA[0], kidB[0] = 1, 2
	wrapped, err := mk.Wrap([]byte("0123456789abcdef"), kidA[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mk.Unwrap(wrapped, kidB[:]); err == nil {
		t.Fatal("wrapped key unwrapped under a different KID")
	}
}

func TestGetUnknownKID(t *testing.T) {
	fs, _ := OpenFileStore(filepath.Join(t.TempDir(), "k.json"), testMaster(t))
	if _, err := fs.Get(KeyID{}); err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestLoadOrCreateLocalMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "master.key")
	a, created, err := LoadOrCreateLocalMasterKey(path)
	if err != nil || !created {
		t.Fatalf("create: %v created=%v", err, created)
	}
	b, created, err := LoadOrCreateLocalMasterKey(path)
	if err != nil || created {
		t.Fatalf("load: %v created=%v", err, created)
	}
	if a.ID() != b.ID() {
		t.Fatal("reloaded master key differs")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("master key mode = %v, want 0600", info.Mode().Perm())
	}
}

func fmtHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}
