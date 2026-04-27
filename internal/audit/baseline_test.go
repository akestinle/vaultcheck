package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func baselineSecrets() []Secret {
	return []Secret{
		{Path: "secret/a", Key: "pass", Value: "abc", CreatedAt: time.Now()},
		{Path: "secret/b", Key: "token", Value: "xyz", CreatedAt: time.Now()},
	}
}

func TestNewBaseline_ContainsAllSecrets(t *testing.T) {
	b := NewBaseline(baselineSecrets())
	if len(b.Secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(b.Secrets))
	}
}

func TestNewBaseline_IndexedByPath(t *testing.T) {
	b := NewBaseline(baselineSecrets())
	if _, ok := b.Secrets["secret/a"]; !ok {
		t.Fatal("expected secret/a in baseline")
	}
}

func TestSaveAndLoadBaseline_RoundTrip(t *testing.T) {
	b := NewBaseline(baselineSecrets())
	tmp := filepath.Join(t.TempDir(), "baseline.json")
	if err := SaveBaseline(b, tmp); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadBaseline(tmp)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Secrets) != len(b.Secrets) {
		t.Fatalf("expected %d secrets, got %d", len(b.Secrets), len(loaded.Secrets))
	}
}

func TestLoadBaseline_NotFound(t *testing.T) {
	_, err := LoadBaseline("/nonexistent/baseline.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSaveBaseline_BadPath(t *testing.T) {
	b := NewBaseline(nil)
	err := SaveBaseline(b, "/nonexistent/dir/baseline.json")
	if err == nil {
		t.Fatal("expected error for bad path")
	}
	_ = os.Remove("/nonexistent/dir/baseline.json")
}
