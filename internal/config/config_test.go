package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opendrm.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaults(t *testing.T) {
	path := write(t, `{"policies":[{"name":"paid","max_streams":2}]}`)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if c.Listen != ":8080" || c.DataDir != filepath.Join(dir, "data") ||
		c.MasterKeyFile != filepath.Join(dir, "data", "master.key") ||
		c.TokenSecretEnv != "OPENDRM_TOKEN_SECRET" || c.StreamLeaseSeconds != 600 || c.TokenLeewaySeconds != 5 {
		t.Fatalf("defaults: %+v", c)
	}
	if c.PolicyMap()["paid"].MaxStreams != 2 {
		t.Fatal("policy map")
	}
}

func TestValidation(t *testing.T) {
	for body, want := range map[string]string{
		`{}`:                         "at least one policy",
		`{"policies":[{"name":""}]}`: "needs a name",
		`{"policies":[{"name":"a"},{"name":"a"}]}`:     "defined twice",
		`{"policies":[{"name":"a","max_streams":-1}]}`: "negative",
	} {
		if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", body, err, want)
		}
	}
}

func TestTokenSecret(t *testing.T) {
	c := &Config{TokenSecretEnv: "OPENDRM_TEST_SECRET"}
	t.Setenv("OPENDRM_TEST_SECRET", "short")
	if _, err := c.TokenSecret(); err == nil {
		t.Fatal("short secret accepted")
	}
	t.Setenv("OPENDRM_TEST_SECRET", strings.Repeat("x", 32))
	if s, err := c.TokenSecret(); err != nil || len(s) != 32 {
		t.Fatalf("secret: %v", err)
	}
}
