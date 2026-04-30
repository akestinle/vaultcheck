package audit

import (
	"bytes"
	"testing"
)

func TestNewPinset_NotNil(t *testing.T) {
	ps := NewPinset()
	if ps == nil {
		t.Fatal("expected non-nil Pinset")
	}
}

func TestPinset_Add_Valid(t *testing.T) {
	ps := NewPinset()
	if err := ps.Add("group1", []string{"secret/a", "secret/b"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e, ok := ps.Get("group1")
	if !ok {
		t.Fatal("expected entry to exist")
	}
	if len(e.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(e.Paths))
	}
}

func TestPinset_Add_EmptyName(t *testing.T) {
	ps := NewPinset()
	if err := ps.Add("", []string{"secret/a"}); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestPinset_Add_NoPaths(t *testing.T) {
	ps := NewPinset()
	if err := ps.Add("group1", nil); err == nil {
		t.Fatal("expected error for nil paths")
	}
}

func TestPinset_Remove_Existing(t *testing.T) {
	ps := NewPinset()
	_ = ps.Add("group1", []string{"secret/a"})
	if !ps.Remove("group1") {
		t.Fatal("expected Remove to return true")
	}
	if _, ok := ps.Get("group1"); ok {
		t.Fatal("expected entry to be gone")
	}
}

func TestPinset_Remove_Missing(t *testing.T) {
	ps := NewPinset()
	if ps.Remove("nonexistent") {
		t.Fatal("expected Remove to return false for missing entry")
	}
}

func TestPinset_Contains_True(t *testing.T) {
	ps := NewPinset()
	_ = ps.Add("group1", []string{"secret/a", "secret/b"})
	if !ps.Contains("group1", "secret/a") {
		t.Fatal("expected Contains to return true")
	}
}

func TestPinset_Contains_False(t *testing.T) {
	ps := NewPinset()
	_ = ps.Add("group1", []string{"secret/a"})
	if ps.Contains("group1", "secret/z") {
		t.Fatal("expected Contains to return false")
	}
}

func TestPinset_Entries_Sorted(t *testing.T) {
	ps := NewPinset()
	_ = ps.Add("zebra", []string{"secret/z"})
	_ = ps.Add("alpha", []string{"secret/a"})
	entries := ps.Entries()
	if len(entries) != 2 || entries[0].Name != "alpha" {
		t.Fatalf("expected sorted entries, got %v", entries)
	}
}

func TestWritePinset_Empty(t *testing.T) {
	ps := NewPinset()
	var buf bytes.Buffer
	WritePinset(&buf, ps)
	if buf.String() == "" {
		t.Fatal("expected non-empty output")
	}
}

func TestWritePinset_WithEntries(t *testing.T) {
	ps := NewPinset()
	_ = ps.Add("infra", []string{"secret/db", "secret/cache"})
	var buf bytes.Buffer
	WritePinset(&buf, ps)
	out := buf.String()
	if out == "" {
		t.Fatal("expected output")
	}
	if !bytes.Contains([]byte(out), []byte("infra")) {
		t.Error("expected pinset name in output")
	}
}
