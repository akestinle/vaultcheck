package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Policy represents a Vault policy with its name and rules.
type Policy struct {
	Name  string `json:"name"`
	Rules string `json:"rules"`
}

// LoadFromFile reads a policy from a JSON or HCL file.
// JSON files must contain {"name": "...", "rules": "..."}.
// HCL/plain files are treated as raw rules; the filename (sans extension) is used as the name.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read file %q: %w", path, err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		var p Policy
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("policy: parse JSON %q: %w", path, err)
		}
		if p.Name == "" {
			return nil, fmt.Errorf("policy: missing name in %q", path)
		}
		if p.Rules == "" {
			return nil, fmt.Errorf("policy: missing rules in %q", path)
		}
		return &p, nil
	}

	// Treat as raw HCL / text rules.
	base := filepath.Base(path)
	name := strings.TrimSuffix(base, ext)
	if name == "" {
		return nil, fmt.Errorf("policy: cannot derive name from path %q", path)
	}
	return &Policy{
		Name:  name,
		Rules: string(data),
	}, nil
}

// LoadDir loads all policy files from a directory.
// Supported extensions: .json, .hcl, .txt.
func LoadDir(dir string) ([]*Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("policy: read dir %q: %w", dir, err)
	}

	var policies []*Policy
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".json" && ext != ".hcl" && ext != ".txt" {
			continue
		}
		p, err := LoadFromFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, nil
}
