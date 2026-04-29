package audit

import (
	"fmt"
	"io"
	"sort"
	"time"
)

// PinEntry records a secret path pinned at a specific version/value hash.
type PinEntry struct {
	Path      string    `json:"path"`
	ValueHash string    `json:"value_hash"`
	PinnedAt  time.Time `json:"pinned_at"`
	PinnedBy  string    `json:"pinned_by"`
}

// Pinner tracks which secrets are pinned and detects drift from their pinned state.
type Pinner struct {
	pins map[string]PinEntry
}

// NewPinner returns an empty Pinner.
func NewPinner() *Pinner {
	return &Pinner{pins: make(map[string]PinEntry)}
}

// Pin records the current value hash of a secret as its pinned state.
func (p *Pinner) Pin(path, valueHash, pinnedBy string) {
	if path == "" || valueHash == "" {
		return
	}
	p.pins[path] = PinEntry{
		Path:      path,
		ValueHash: valueHash,
		PinnedAt:  time.Now().UTC(),
		PinnedBy:  pinnedBy,
	}
}

// Unpin removes a pin for the given path. No-op if not pinned.
func (p *Pinner) Unpin(path string) {
	delete(p.pins, path)
}

// IsPinned reports whether a path has a recorded pin.
func (p *Pinner) IsPinned(path string) bool {
	_, ok := p.pins[path]
	return ok
}

// PinDrift compares current secrets against pinned entries and returns paths
// whose value hash differs from the pinned hash.
func (p *Pinner) PinDrift(secrets []Secret) []string {
	var drifted []string
	for _, s := range secrets {
		entry, ok := p.pins[s.Path]
		if !ok {
			continue
		}
		if s.ValueHash != entry.ValueHash {
			drifted = append(drifted, s.Path)
		}
	}
	sort.Strings(drifted)
	return drifted
}

// WritePinReport writes a human-readable pin drift report to w.
func (p *Pinner) WritePinReport(w io.Writer, drifted []string) {
	if len(drifted) == 0 {
		fmt.Fprintln(w, "pin drift: no drift detected")
		return
	}
	fmt.Fprintf(w, "pin drift: %d secret(s) have changed since pinning\n", len(drifted))
	for _, path := range drifted {
		entry := p.pins[path]
		fmt.Fprintf(w, "  DRIFTED  %s  (pinned by %s at %s)\n",
			path, entry.PinnedBy, entry.PinnedAt.Format(time.RFC3339))
	}
}
