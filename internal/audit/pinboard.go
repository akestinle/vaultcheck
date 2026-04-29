package audit

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// PinboardEntry records a secret path along with an annotation and timestamp.
type PinboardEntry struct {
	Path       string    `json:"path"`
	Annotation string    `json:"annotation"`
	PinnedAt   time.Time `json:"pinned_at"`
}

// Pinboard holds a collection of annotated secret paths for review.
type Pinboard struct {
	entries map[string]PinboardEntry
}

// NewPinboard returns an empty Pinboard.
func NewPinboard() *Pinboard {
	return &Pinboard{entries: make(map[string]PinboardEntry)}
}

// Add adds or replaces an entry for the given path with an annotation.
func (p *Pinboard) Add(path, annotation string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("pinboard: path must not be empty")
	}
	p.entries[path] = PinboardEntry{
		Path:       path,
		Annotation: annotation,
		PinnedAt:   time.Now().UTC(),
	}
	return nil
}

// Remove deletes the entry for the given path. Returns false if not found.
func (p *Pinboard) Remove(path string) bool {
	if _, ok := p.entries[path]; !ok {
		return false
	}
	delete(p.entries, path)
	return true
}

// Has reports whether the given path is in the pinboard.
func (p *Pinboard) Has(path string) bool {
	_, ok := p.entries[path]
	return ok
}

// Entries returns all entries sorted by path.
func (p *Pinboard) Entries() []PinboardEntry {
	out := make([]PinboardEntry, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Path < out[j].Path
	})
	return out
}

// WritePinboard writes a human-readable table of pinboard entries to w.
func WritePinboard(w io.Writer, pb *Pinboard) {
	entries := pb.Entries()
	if len(entries) == 0 {
		fmt.Fprintln(w, "pinboard: no entries")
		return
	}
	fmt.Fprintf(w, "%-40s  %-30s  %s\n", "PATH", "ANNOTATION", "PINNED AT")
	fmt.Fprintln(w, strings.Repeat("-", 85))
	for _, e := range entries {
		fmt.Fprintf(w, "%-40s  %-30s  %s\n", e.Path, e.Annotation, e.PinnedAt.Format(time.RFC3339))
	}
}
