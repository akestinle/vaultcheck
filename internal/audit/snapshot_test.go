package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func snapshotSecrets() []Secret {
	return []Secret{
		{Path: "secret/alpha", Key: "api_key", Value: "abc123", CreatedAt: time.Now().Add(-48 * time.Hour)},
		{Path: "secret/beta", Key: "db_pass", Value: "xyz789", CreatedAt: time.Now().Add(-10 * time.Hour)},
	}
}

func TestNewSnapshot_FieldsSet(t *testing.T) {
	secrets := snapshotSecrets()
	snap := NewSnapshot(secrets, "test-label")
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.Count != 2 {
		t.Errorf("expected count 2, got %d", snap.Count)
	}
	if snap.Label != "test-label" {
		t.Errorf("expected label 'test-label', got %q", snap.Label)
	}
	if snap.ID == "" {
		t.Error("expected non-empty ID")
	}
	if snap.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestNewSnapshot_EmptySecrets(t *testing.T) {
	snap := NewSnapshot([]Secret{}, "")
	if snap.Count != 0 {
		t.Errorf("expected count 0, got %d", snap.Count)
	}
}

func TestSaveAndLoadSnapshot_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	original := NewSnapshot(snapshotSecrets(), "roundtrip")
	if err := SaveSnapshot(dir, original); err != nil {
		t.Fatalf("SaveSnapshot error: %v", err)
	}
	path := filepath.Join(dir, original.ID+".json")
	loaded, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("LoadSnapshot error: %v", err)
	}
	if loaded.ID != original.ID {
		t.Errorf("ID mismatch: got %q, want %q", loaded.ID, original.ID)
	}
	if loaded.Count != original.Count {
		t.Errorf("Count mismatch: got %d, want %d", loaded.Count, original.Count)
	}
	if loaded.Label != original.Label {
		t.Errorf("Label mismatch: got %q, want %q", loaded.Label, original.Label)
	}
}

func TestLoadSnapshot_NotFound(t *testing.T) {
	_, err := LoadSnapshot("/nonexistent/path/snap.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestSaveSnapshot_CreatesDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "nested", "snapshots")
	snap := NewSnapshot(snapshotSecrets(), "dir-test")
	if err := SaveSnapshot(dir, snap); err != nil {
		t.Fatalf("SaveSnapshot error: %v", err)
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("expected directory to be created")
	}
}
