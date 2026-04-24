package vault

import (
	"errors"
	"fmt"
	"os"

	vaultapi "github.com/hashicorp/vault/api"
)

// Client wraps the Vault API client with convenience methods.
type Client struct {
	logical *vaultapi.Logical
	sys     *vaultapi.Sys
	raw     *vaultapi.Client
}

// Config holds connection parameters for Vault.
type Config struct {
	Address string
	Token   string
	TLSSkip bool
}

// NewClient creates a new authenticated Vault client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		cfg.Address = os.Getenv("VAULT_ADDR")
	}
	if cfg.Token == "" {
		cfg.Token = os.Getenv("VAULT_TOKEN")
	}
	if cfg.Address == "" {
		return nil, errors.New("vault address is required (set VAULT_ADDR or --address flag)")
	}
	if cfg.Token == "" {
		return nil, errors.New("vault token is required (set VAULT_TOKEN or --token flag)")
	}

	apiCfg := vaultapi.DefaultConfig()
	apiCfg.Address = cfg.Address

	if cfg.TLSSkip {
		tlsCfg := &vaultapi.TLSConfig{Insecure: true}
		if err := apiCfg.ConfigureTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("configuring TLS: %w", err)
		}
	}

	raw, err := vaultapi.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}
	raw.SetToken(cfg.Token)

	return &Client{
		logical: raw.Logical(),
		sys:     raw.Sys(),
		raw:     raw,
	}, nil
}

// Health checks connectivity and token validity.
func (c *Client) Health() error {
	_, err := c.sys.Health()
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}
	return nil
}

// ReadSecret reads a KV secret at the given path.
func (c *Client) ReadSecret(path string) (map[string]interface{}, error) {
	secret, err := c.logical.Read(path)
	if err != nil {
		return nil, fmt.Errorf("reading secret at %q: %w", path, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("no secret found at path %q", path)
	}
	data, ok := secret.Data["data"]
	if !ok {
		return secret.Data, nil
	}
	if m, ok := data.(map[string]interface{}); ok {
		return m, nil
	}
	return secret.Data, nil
}
