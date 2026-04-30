package audit

import (
	"os"
	"testing"
)

func TestNewFreezer_EmptyDir(t *testing.T) {
	_, err := NewFreezer("")
	if err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestNewFreezer_CreatesDir(t *testing.T) {
	dir := t.TempDir()
	subDir := dir + "/freeze_state"
	f, err := NewFreezer(subDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil freezer")
	}
	if _, err := os.Stat(subDir); os.IsNotExist(err) {
		t.Fatal("expected directory to be created")
	}
}

func TestFreezer_Freeze_And_IsFrozen(t *testing.T) {
	dir := t.TempDir()
	f, _ := NewFreezer(dir)

	if f.IsFrozen("secret/db") {
		t.Fatal("should not be frozen initially")
	}
	if err := f.Freeze("secret/db", "compliance hold", "alice"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.IsFrozen("secret/db") {
		t.Fatal("expected path to be frozen")
	}
}

func TestFreezer_Freeze_EmptyPath_Ignored(t *testing.T) {
	dir := t.TempDir()
	f, _ := NewFreezer(dir)
	if err := f.Freeze("", "reason", "bob"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.Entries()) != 0 {
		t.Fatal("empty path should not be stored")
	}
}

func TestFreezer_Unfreeze_Removes(t *testing.T) {
	dir := t.TempDir()
	f, _ := NewFreezer(dir)
	_ = f.Freeze("secret/api", "hold", "carol")
	if err := f.Unfreeze("secret/api"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.IsFrozen("secret/api") {
		t.Fatal("expected path to be unfrozen")
	}
}

func TestFreezer_Unfreeze_NonExistent_NoError(t *testing.T) {
	dir := t.TempDir()
	f, _ := NewFreezer(dir)
	if err := f.Unfreeze("secret/missing"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFreezer_Entries_ReturnsAll(t *testing.T) {
	dir := t.TempDir()
	f, _ := NewFreezer(dir)
	_ = f.Freeze("secret/a", "r1", "u1")
	_ = f.Freeze("secret/b", "r2", "u2")
	if len(f.Entries()) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(f.Entries()))
	}
}

func TestFreezer_Persistence_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	f1, _ := NewFreezer(dir)
	_ = f1.Freeze("secret/persist", "audit", "dave")

	f2, err := NewFreezer(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f2.IsFrozen("secret/persist") {
		t.Fatal("expected frozen path to persist across instances")
	}
}
