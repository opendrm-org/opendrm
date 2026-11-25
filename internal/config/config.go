// Package config loads opendrm.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/opendrm-org/opendrm/internal/policy"
)

// Config is the server configuration. Secrets are never stored here: the
// token secret is read from the environment variable named by TokenSecretEnv.
type Config struct {
	Listen  string `json:"listen"`
	DataDir string `json:"data_dir"`
	// MasterKeyFile holds the hex master key. Default: <data_dir>/master.key.
	MasterKeyFile string `json:"master_key_file"`
	// KeysFile holds wrapped content keys. Default: <data_dir>/keys.json.
	KeysFile string `json:"keys_file"`
	// TokenSecretEnv names the env var holding the playback-token secret.
	TokenSecretEnv string `json:"token_secret_env"`
	// TokenLeewaySeconds absorbs clock skew. Default 5.
	TokenLeewaySeconds int `json:"token_leeway_seconds"`
	// StreamLeaseSeconds is how long a stream holds its slot without a renewal. Default 600.
	StreamLeaseSeconds int             `json:"stream_lease_seconds"`
	CountryHeader      string          `json:"country_header"`
	AllowedOrigins     []string        `json:"allowed_origins"`
	Policies           []policy.Policy `json:"policies"`
}

// Load reads path, applies defaults and validates.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.applyDefaults(filepath.Dir(path))
	return c, c.validate()
}

func (c *Config) applyDefaults(base string) {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if !filepath.IsAbs(c.DataDir) {
		c.DataDir = filepath.Join(base, c.DataDir)
	}
	if c.MasterKeyFile == "" {
		c.MasterKeyFile = filepath.Join(c.DataDir, "master.key")
	}
	if c.KeysFile == "" {
		c.KeysFile = filepath.Join(c.DataDir, "keys.json")
	}
	if c.TokenSecretEnv == "" {
		c.TokenSecretEnv = "OPENDRM_TOKEN_SECRET"
	}
	if c.TokenLeewaySeconds == 0 {
		c.TokenLeewaySeconds = 5
	}
	if c.StreamLeaseSeconds == 0 {
		c.StreamLeaseSeconds = 600
	}
}

func (c *Config) validate() error {
	if len(c.Policies) == 0 {
		return errors.New("config: define at least one policy")
	}
	seen := map[string]bool{}
	for _, p := range c.Policies {
		if p.Name == "" {
			return errors.New("config: every policy needs a name")
		}
		if seen[p.Name] {
			return fmt.Errorf("config: policy %q defined twice", p.Name)
		}
		seen[p.Name] = true
		if p.MaxStreams < 0 || p.MaxTokenAge < 0 {
			return fmt.Errorf("config: policy %q has a negative limit", p.Name)
		}
	}
	return nil
}

// PolicyMap indexes policies by name.
func (c *Config) PolicyMap() map[string]policy.Policy {
	m := make(map[string]policy.Policy, len(c.Policies))
	for _, p := range c.Policies {
		m[p.Name] = p
	}
	return m
}

// TokenSecret reads the secret from the environment.
func (c *Config) TokenSecret() ([]byte, error) {
	s := os.Getenv(c.TokenSecretEnv)
	if len(s) < 32 {
		return nil, fmt.Errorf("set %s to a random secret of at least 32 characters (try: openssl rand -hex 32)", c.TokenSecretEnv)
	}
	return []byte(s), nil
}
