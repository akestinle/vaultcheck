package audit

import (
	"testing"
	"time"
)

// watchlistMatchSecrets provides a shared fixture for match-focused tests.
var watchlistMatchSecrets = []Secret{
	{Path: "secret/payments/api_key", Value: "tok_live_abc", UpdatedAt: time.Now().AddDate(0, -2, 0)},
	{Path: "secret/infra/ssh_key", Value: "-----BEGIN RSA", UpdatedAt: time.Now().AddDate(0, 0, -5)},
	{Path: "secret/app/db_pass", Value: "hunter2", UpdatedAt: time.Now().AddDate(-1, 0, 0)},
	{Path: "secret/app/session_token", Value: "sess_xyz", UpdatedAt: time.Now().AddDate(0, -3, 0)},
}

func TestWatchlist_Match_None(t *testing.T) {
	wl := NewWatchlist()
	matched := wl.Match(watchlistMatchSecrets)
	if len(matched) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matched))
	}
}

func TestWatchlist_Match_All(t *testing.T) {
	wl := NewWatchlist()
	for _, s := range watchlistMatchSecrets {
		_ = wl.Add(s.Path, "", false)
	}
	matched := wl.Match(watchlistMatchSecrets)
	if len(matched) != len(watchlistMatchSecrets) {
		t.Errorf("expected %d matches, got %d", len(watchlistMatchSecrets), len(matched))
	}
}

func TestWatchlist_Match_Subset(t *testing.T) {
	wl := NewWatchlist()
	_ = wl.Add("secret/payments/api_key", "PCI", true)
	_ = wl.Add("secret/app/db_pass", "sensitive", true)
	matched := wl.Match(watchlistMatchSecrets)
	if len(matched) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matched))
	}
	paths := map[string]bool{}
	for _, s := range matched {
		paths[s.Path] = true
	}
	if !paths["secret/payments/api_key"] || !paths["secret/app/db_pass"] {
		t.Error("unexpected matched paths")
	}
}

func TestWatchlist_Entries_Sorted(t *testing.T) {
	wl := NewWatchlist()
	_ = wl.Add("z/path", "", false)
	_ = wl.Add("a/path", "", false)
	_ = wl.Add("m/path", "", false)
	entries := wl.Entries()
	if entries[0].Path != "a/path" || entries[1].Path != "m/path" || entries[2].Path != "z/path" {
		t.Errorf("entries not sorted: %v", entries)
	}
}

func TestWatchlist_AlertOnChange_Preserved(t *testing.T) {
	wl := NewWatchlist()
	_ = wl.Add("secret/critical", "must alert", true)
	entries := wl.Entries()
	if len(entries) == 0 {
		t.Fatal("expected at least one entry")
	}
	if !entries[0].AlertOnChange {
		t.Error("expected AlertOnChange to be true")
	}
}
