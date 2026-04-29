package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewWatchlist_NotNil(t *testing.T) {
	wl := NewWatchlist()
	if wl == nil {
		t.Fatal("expected non-nil Watchlist")
	}
}

func TestWatchlist_Add_Valid(t *testing.T) {
	wl := NewWatchlist()
	if err := wl.Add("secret/db/password", "high value", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !wl.Contains("secret/db/password") {
		t.Error("expected path to be on watchlist")
	}
}

func TestWatchlist_Add_EmptyPath(t *testing.T) {
	wl := NewWatchlist()
	if err := wl.Add("", "reason", false); err == nil {
		t.Error("expected error for empty path")
	}
}

func TestWatchlist_Add_ReplacesExisting(t *testing.T) {
	wl := NewWatchlist()
	_ = wl.Add("secret/a", "first", false)
	_ = wl.Add("secret/a", "second", true)
	entries := wl.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Reason != "second" {
		t.Errorf("expected reason 'second', got %q", entries[0].Reason)
	}
}

func TestWatchlist_Remove_Existing(t *testing.T) {
	wl := NewWatchlist()
	_ = wl.Add("secret/x", "", false)
	if !wl.Remove("secret/x") {
		t.Error("expected Remove to return true")
	}
	if wl.Contains("secret/x") {
		t.Error("expected path to be removed")
	}
}

func TestWatchlist_Remove_Missing(t *testing.T) {
	wl := NewWatchlist()
	if wl.Remove("does/not/exist") {
		t.Error("expected Remove to return false for missing path")
	}
}

func TestWatchlist_Match(t *testing.T) {
	wl := NewWatchlist()
	_ = wl.Add("secret/db", "", false)
	secrets := []Secret{
		{Path: "secret/db"},
		{Path: "secret/api"},
	}
	matched := wl.Match(secrets)
	if len(matched) != 1 || matched[0].Path != "secret/db" {
		t.Errorf("unexpected match result: %v", matched)
	}
}

func TestWriteWatchlist_Empty(t *testing.T) {
	var buf bytes.Buffer
	WriteWatchlist(nil, &buf)
	if !strings.Contains(buf.String(), "empty") {
		t.Errorf("expected empty message, got: %s", buf.String())
	}
}

func TestWriteWatchlist_Entries(t *testing.T) {
	wl := NewWatchlist()
	_ = wl.Add("secret/db", "critical", true)
	var buf bytes.Buffer
	WriteWatchlist(wl.Entries(), &buf)
	if !strings.Contains(buf.String(), "secret/db") {
		t.Errorf("expected path in output, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "yes") {
		t.Errorf("expected alert=yes in output, got: %s", buf.String())
	}
}
