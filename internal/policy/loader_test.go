package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile_JSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "my-policy.json")
	content := `{"name":"my-policy","rules":"path \"secret/*\" { capabilities = [\"read\"] }"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "my-policy" {
		t.Errorf("name: got %q, want %q", p.Name, "my-policy")
	}
	if p.Rules == "" {
		t.Error("rules should not be empty")
	}
}

func TestLoadFromFile_HCL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.hcl")
	rules := `path "sys/*" { capabilities = ["sudo"] }`
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "admin" {
		t.Errorf("name: got %q, want %q", p.Name, "admin")
	}
	if p.Rules != rules {
		t.Errorf("rules mismatch")
	}
}

func TestLoadFromFile_JSON_MissingName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"rules":"something"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/policy.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()

	files := map[string]string{
		"pol1.hcl":  `path "kv/*" { capabilities = ["read"] }`,
		"pol2.json": `{"name":"pol2","rules":"path \"auth/*\" { capabilities = [\"list\"] }"}`,
		"ignore.md": "# not a policy",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	policies, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
}

func TestLoadDir_Empty(t *testing.T) {
	dir := t.TempDir()
	policies, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(policies))
	}
}
