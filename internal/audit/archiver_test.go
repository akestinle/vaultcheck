package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewArchiver_EmptyDir(t *testing.T) {
	_, err := NewArchiver("")
	if err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestNewArchiver_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "archive")
	a, err := NewArchiver(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil archiver")
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatal("expected directory to be created")
	}
}

func TestArchiver_Archive_WritesFile(t *testing.T) {
	dir := t.TempDir()
	a, _ := NewArchiver(dir)

	secrets := []Secret{
		{Path: "secret/a", Key: "password", Value: "s3cr3t", CreatedAt: time.Now()},
	}

	path, err := a.Archive(secrets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path == "" {
		t.Fatal("expected non-empty path")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("archive file not found at %s", path)
	}
}

func TestArchiver_Archive_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	a, _ := NewArchiver(dir)

	now := time.Now().UTC().Truncate(time.Second)
	secrets := []Secret{
		{Path: "secret/db", Key: "pass", Value: "abc123", CreatedAt: now},
	}

	path, err := a.Archive(secrets)
	if err != nil {
		t.Fatalf("archive failed: %v", err)
	}

	entry, err := LoadArchive(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if len(entry.Secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(entry.Secrets))
	}
	if entry.Secrets[0].Path != "secret/db" {
		t.Errorf("expected path secret/db, got %s", entry.Secrets[0].Path)
	}
	if entry.ArchivedAt.IsZero() {
		t.Error("expected non-zero ArchivedAt")
	}
}

func TestLoadArchive_NotFound(t *testing.T) {
	_, err := LoadArchive("/nonexistent/path/archive.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
