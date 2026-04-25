package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// SecretMeta holds metadata about a single secret key discovered in Vault.
type SecretMeta struct {
	Path      string
	Key       string
	UpdatedAt time.Time
}

// VaultLister is the minimal Vault client interface required by Scanner.
type VaultLister interface {
	List(path string) (*vaultapi.Secret, error)
	Read(path string) (*vaultapi.Secret, error)
}

// Scanner walks a Vault KV mount and collects SecretMeta entries.
type Scanner struct {
	client VaultLister
	mount  string
}

// NewScanner creates a Scanner for the given KV mount path.
func NewScanner(client VaultLister, mount string) (*Scanner, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	if mount == "" {
		mount = "secret"
	}
	return &Scanner{client: client, mount: mount}, nil
}

// Scan recursively lists the mount and returns all discovered secrets.
func (s *Scanner) Scan(ctx context.Context) ([]SecretMeta, error) {
	return s.walk(ctx, s.mount+"/")
}

func (s *Scanner) walk(ctx context.Context, prefix string) ([]SecretMeta, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	secret, err := s.client.List(prefix)
	if err != nil {
		return nil, fmt.Errorf("list %q: %w", prefix, err)
	}
	if secret == nil {
		return nil, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, nil
	}

	var results []SecretMeta
	for _, raw := range keys {
		k, _ := raw.(string)
		if strings.HasSuffix(k, "/") {
			sub, err := s.walk(ctx, prefix+k)
			if err != nil {
				return nil, err
			}
			results = append(results, sub...)
			continue
		}
		meta, err := s.readMeta(prefix + k)
		if err != nil {
			return nil, err
		}
		results = append(results, meta...)
	}
	return results, nil
}

func (s *Scanner) readMeta(fullPath string) ([]SecretMeta, error) {
	secret, err := s.client.Read(fullPath)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", fullPath, err)
	}
	if secret == nil {
		return nil, nil
	}
	var metas []SecretMeta
	for k := range secret.Data {
		metas = append(metas, SecretMeta{
			Path:      fullPath,
			Key:       k,
			UpdatedAt: time.Now(),
		})
	}
	return metas, nil
}
