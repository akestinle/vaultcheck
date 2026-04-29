package audit

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// WatchEntry represents a single watched secret path with metadata.
type WatchEntry struct {
	Path      string
	AddedAt   time.Time
	Reason    string
	AlertOnChange bool
}

// Watchlist tracks a set of secret paths for heightened monitoring.
type Watchlist struct {
	entries map[string]*WatchEntry
}

// NewWatchlist creates an empty Watchlist.
func NewWatchlist() *Watchlist {
	return &Watchlist{entries: make(map[string]*WatchEntry)}
}

// Add registers a path on the watchlist. Duplicate paths are silently replaced.
func (w *Watchlist) Add(path, reason string, alertOnChange bool) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("watchlist: path must not be empty")
	}
	w.entries[path] = &WatchEntry{
		Path:          path,
		AddedAt:       time.Now().UTC(),
		Reason:        reason,
		AlertOnChange: alertOnChange,
	}
	return nil
}

// Remove deletes a path from the watchlist. Returns false if the path was not present.
func (w *Watchlist) Remove(path string) bool {
	if _, ok := w.entries[path]; !ok {
		return false
	}
	delete(w.entries, path)
	return true
}

// Contains reports whether path is on the watchlist.
func (w *Watchlist) Contains(path string) bool {
	_, ok := w.entries[path]
	return ok
}

// Entries returns all WatchEntry values sorted by path.
func (w *Watchlist) Entries() []*WatchEntry {
	out := make([]*WatchEntry, 0, len(w.entries))
	for _, e := range w.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Match filters a slice of secrets and returns only those on the watchlist.
func (w *Watchlist) Match(secrets []Secret) []Secret {
	var matched []Secret
	for _, s := range secrets {
		if w.Contains(s.Path) {
			matched = append(matched, s)
		}
	}
	return matched
}

// WriteWatchlist writes a human-readable table of watchlist entries to w.
func WriteWatchlist(entries []*WatchEntry, w io.Writer) {
	if len(entries) == 0 {
		fmt.Fprintln(w, "watchlist is empty")
		return
	}
	fmt.Fprintf(w, "%-40s %-8s %-26s %s\n", "PATH", "ALERT", "ADDED", "REASON")
	for _, e := range entries {
		alert := "no"
		if e.AlertOnChange {
			alert = "yes"
		}
		fmt.Fprintf(w, "%-40s %-8s %-26s %s\n", e.Path, alert, e.AddedAt.Format(time.RFC3339), e.Reason)
	}
}
