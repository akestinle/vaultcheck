package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewPinboard_NotNil(t *testing.T) {
	pb := NewPinboard()
	if pb == nil {
		t.Fatal("expected non-nil Pinboard")
	}
}

func TestPinboard_Add_Valid(t *testing.T) {
	pb := NewPinboard()
	if err := pb.Add("secret/foo", "needs review"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pb.Has("secret/foo") {
		t.Error("expected path to be present after Add")
	}
}

func TestPinboard_Add_EmptyPath(t *testing.T) {
	pb := NewPinboard()
	if err := pb.Add("", "note"); err == nil {
		t.Error("expected error for empty path")
	}
}

func TestPinboard_Add_ReplacesExisting(t *testing.T) {
	pb := NewPinboard()
	_ = pb.Add("secret/foo", "first")
	_ = pb.Add("secret/foo", "second")
	entries := pb.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Annotation != "second" {
		t.Errorf("expected annotation 'second', got %q", entries[0].Annotation)
	}
}

func TestPinboard_Remove_Existing(t *testing.T) {
	pb := NewPinboard()
	_ = pb.Add("secret/bar", "note")
	if !pb.Remove("secret/bar") {
		t.Error("expected Remove to return true for existing entry")
	}
	if pb.Has("secret/bar") {
		t.Error("expected entry to be absent after Remove")
	}
}

func TestPinboard_Remove_Missing(t *testing.T) {
	pb := NewPinboard()
	if pb.Remove("nonexistent") {
		t.Error("expected Remove to return false for missing entry")
	}
}

func TestPinboard_Entries_SortedByPath(t *testing.T) {
	pb := NewPinboard()
	_ = pb.Add("secret/zzz", "")
	_ = pb.Add("secret/aaa", "")
	_ = pb.Add("secret/mmm", "")
	entries := pb.Entries()
	for i := 1; i < len(entries); i++ {
		if entries[i].Path < entries[i-1].Path {
			t.Errorf("entries not sorted: %s before %s", entries[i-1].Path, entries[i].Path)
		}
	}
}

func TestWritePinboard_Empty(t *testing.T) {
	pb := NewPinboard()
	var buf bytes.Buffer
	WritePinboard(&buf, pb)
	if !strings.Contains(buf.String(), "no entries") {
		t.Errorf("expected 'no entries' message, got: %s", buf.String())
	}
}

func TestWritePinboard_WithEntries(t *testing.T) {
	pb := NewPinboard()
	_ = pb.Add("secret/alpha", "check expiry")
	var buf bytes.Buffer
	WritePinboard(&buf, pb)
	if !strings.Contains(buf.String(), "secret/alpha") {
		t.Errorf("expected path in output, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "check expiry") {
		t.Errorf("expected annotation in output, got: %s", buf.String())
	}
}
