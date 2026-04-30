package audit

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// PinsetEntry represents a named collection of pinned secret paths.
type PinsetEntry struct {
	Name  string   `json:"name"`
	Paths []string `json:"paths"`
}

// Pinset manages named groups of pinned secret paths.
type Pinset struct {
	mu      sync.RWMutex
	entries map[string]*PinsetEntry
}

// NewPinset returns an initialised Pinset.
func NewPinset() *Pinset {
	return &Pinset{entries: make(map[string]*PinsetEntry)}
}

// Add creates or replaces a named pinset entry.
func (ps *Pinset) Add(name string, paths []string) error {
	if name == "" {
		return ErrEmptyPath
	}
	if len(paths) == 0 {
		return fmt.Errorf("pinset %q: no paths provided", name)
	}
	copy := make([]string, len(paths))
	for i, p := range paths {
		copy[i] = p
	}
	sort.Strings(copy)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.entries[name] = &PinsetEntry{Name: name, Paths: copy}
	return nil
}

// Remove deletes a named pinset entry. Returns false if not found.
func (ps *Pinset) Remove(name string) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	_, ok := ps.entries[name]
	if ok {
		delete(ps.entries, name)
	}
	return ok
}

// Get retrieves a pinset entry by name.
func (ps *Pinset) Get(name string) (*PinsetEntry, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	e, ok := ps.entries[name]
	return e, ok
}

// Entries returns all pinset entries sorted by name.
func (ps *Pinset) Entries() []*PinsetEntry {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]*PinsetEntry, 0, len(ps.entries))
	for _, e := range ps.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Contains reports whether the named pinset includes the given path.
func (ps *Pinset) Contains(name, path string) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	e, ok := ps.entries[name]
	if !ok {
		return false
	}
	for _, p := range e.Paths {
		if p == path {
			return true
		}
	}
	return false
}

// WritePinset writes a human-readable summary of all pinsets to w.
func WritePinset(w io.Writer, ps *Pinset) {
	entries := ps.Entries()
	if len(entries) == 0 {
		fmt.Fprintln(w, "no pinsets defined")
		return
	}
	for _, e := range entries {
		fmt.Fprintf(w, "[%s] (%d paths)\n", e.Name, len(e.Paths))
		for _, p := range e.Paths {
			fmt.Fprintf(w, "  - %s\n", p)
		}
	}
}
