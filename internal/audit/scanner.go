package audit

import (
	"fmt"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// Scanner walks a Vault instance and collects secrets.
type Scanner struct {
	client  *vaultapi.Client
	// secrets is used in tests to inject pre-canned results.
	secrets []Secret
}

// NewScanner creates a Scanner backed by the given Vault client.
func NewScanner(client *vaultapi.Client) (*Scanner, error) {
	if client == nil {
		return nil, fmt.Errorf("scanner: vault client must not be nil")
	}
	return &Scanner{client: client}, nil
}

// Scan lists secrets reachable from the KV mount root and returns them.
// It respects the PathPrefix and filter options carried in ScanOptions.
func (s *Scanner) Scan(opts ScanOptions) ([]Secret, error) {
	// Allow tests to inject pre-canned secrets.
	if s.secrets != nil {
		filterOpts := opts.ToFilterOptions()
		return Filter(s.secrets, filterOpts), nil
	}

	root := "secret/"
	if opts.PathPrefix != "" {
		root = strings.TrimRight(opts.PathPrefix, "/") + "/"
	}

	var secrets []Secret
	if err := s.walk(root, opts, &secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

// walk recursively lists the given path and collects leaf secrets.
func (s *Scanner) walk(path string, opts ScanOptions, out *[]Secret) error {
	logical := s.client.Logical()
	secret, err := logical.List(path)
	if err != nil {
		return fmt.Errorf("scanner: list %q: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil
	}

	for _, k := range keys {
		key, _ := k.(string)
		if strings.HasSuffix(key, "/") {
			if err := s.walk(path+key, opts, out); err != nil {
				return err
			}
			continue
		}
		sec, err := s.readSecret(path+key, opts)
		if err != nil {
			return err
		}
		*out = append(*out, sec...)
	}
	return nil
}

// readSecret reads a single KV secret and returns one Secret per key.
func (s *Scanner) readSecret(path string, opts ScanOptions) ([]Secret, error) {
	logical := s.client.Logical()
	result, err := logical.Read(path)
	if err != nil {
		return nil, fmt.Errorf("scanner: read %q: %w", path, err)
	}
	if result == nil || result.Data == nil {
		return nil, nil
	}

	asOf := opts.EffectiveAsOf()
	var secrets []Secret
	for k, v := range result.Data {
		val, _ := v.(string)
		sec := Secret{
			Path:      path,
			Key:       k,
			Value:     val,
			UpdatedAt: asOf,
		}
		secrets = append(secrets, sec)
	}
	return secrets, nil
}
