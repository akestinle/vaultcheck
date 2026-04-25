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

// Scanner walks Vault KV paths and collects secret metadata.
type Scanner struct {
	client *vaultapi.Client
	mount  string
}

// NewScanner creates a Scanner for the given Vault client and KV mount point.
func NewScanner(client *vaultapi.Client, mount string) (*Scanner, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	if mount == "" {
		mount = "secret"
	}
	return &Scanner{client: client, mount: mount}, nil
}

// Scan lists all secrets under the given root path and returns their metadata.
func (s *Scanner) Scan(ctx context.Context, root string) ([]SecretMeta, error) {
	var results []SecretMeta
	if err := s.walk(ctx, root, &results); err != nil {
		return nil, err
	}
	return results, nil
}

func (s *Scanner) walk(ctx context.Context, path string, out *[]SecretMeta) error {
	listPath := fmt.Sprintf("%s/metadata/%s", s.mount, path)
	secret, err := s.client.Logical().ListWithContext(ctx, listPath)
	if err != nil {
		return fmt.Errorf("listing %s: %w", listPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil
	}
	for _, k := range keys {
		name, _ := k.(string)
		if strings.HasSuffix(name, "/") {
			subPath := strings.TrimSuffix(path+"/"+strings.TrimSuffix(name, "/"), "/")
			if err := s.walk(ctx, subPath, out); err != nil {
				return err
			}
			continue
		}
		meta, err := s.readMeta(ctx, path+"/"+name)
		if err != nil {
			return err
		}
		*out = append(*out, meta...)
	}
	return nil
}

func (s *Scanner) readMeta(ctx context.Context, path string) ([]SecretMeta, error) {
	readPath := fmt.Sprintf("%s/metadata/%s", s.mount, path)
	secret, err := s.client.Logical().ReadWithContext(ctx, readPath)
	if err != nil {
		return nil, fmt.Errorf("reading metadata %s: %w", readPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	var updatedAt time.Time
	if v, ok := secret.Data["updated_time"].(string); ok {
		updatedAt, _ = time.Parse(time.RFC3339Nano, v)
	}
	var keys []SecretMeta
	if versions, ok := secret.Data["versions"].(map[string]interface{}); ok {
		_ = versions // version details available if needed
	}
	keys = append(keys, SecretMeta{
		Path:      s.mount + "/" + path,
		Key:       path[strings.LastIndex(path, "/")+1:],
		UpdatedAt: updatedAt,
	})
	return keys, nil
}
