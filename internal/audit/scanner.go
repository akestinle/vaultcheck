package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// SecretMeta holds metadata about a secret found during a scan.
type SecretMeta struct {
	Path      string
	Keys      []string
	CreatedAt time.Time
	UpdatedAt time.Time
	Version   int
}

// Scanner walks Vault KV paths and collects secret metadata.
type Scanner struct {
	client *vaultapi.Client
	mount  string
}

// NewScanner creates a Scanner for the given KV mount (e.g. "secret").
func NewScanner(client *vaultapi.Client, mount string) *Scanner {
	return &Scanner{client: client, mount: mount}
}

// Scan recursively lists all secrets under basePath and returns their metadata.
func (s *Scanner) Scan(ctx context.Context, basePath string) ([]SecretMeta, error) {
	var results []SecretMeta
	if err := s.walk(ctx, basePath, &results); err != nil {
		return nil, err
	}
	return results, nil
}

func (s *Scanner) walk(ctx context.Context, path string, out *[]SecretMeta) error {
	listPath := fmt.Sprintf("%s/metadata/%s", s.mount, path)
	secret, err := s.client.Logical().ListWithContext(ctx, listPath)
	if err != nil {
		return fmt.Errorf("list %s: %w", listPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil
	}
	for _, k := range keys {
		key := fmt.Sprintf("%v", k)
		child := strings.TrimSuffix(path+"/"+key, "/")
		if strings.HasSuffix(key, "/") {
			if err := s.walk(ctx, child, out); err != nil {
				return err
			}
			continue
		}
		meta, err := s.readMeta(ctx, child)
		if err != nil {
			return err
		}
		*out = append(*out, meta)
	}
	return nil
}

func (s *Scanner) readMeta(ctx context.Context, path string) (SecretMeta, error) {
	metaPath := fmt.Sprintf("%s/metadata/%s", s.mount, path)
	secret, err := s.client.Logical().ReadWithContext(ctx, metaPath)
	if err != nil {
		return SecretMeta{}, fmt.Errorf("read meta %s: %w", metaPath, err)
	}
	meta := SecretMeta{Path: path}
	if secret != nil && secret.Data != nil {
		if v, ok := secret.Data["current_version"].(float64); ok {
			meta.Version = int(v)
		}
		if versions, ok := secret.Data["versions"].(map[string]interface{}); ok {
			meta.Keys = make([]string, 0, len(versions))
			for vk := range versions {
				meta.Keys = append(meta.Keys, vk)
			}
		}
	}
	return meta, nil
}
