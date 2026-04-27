package audit

import (
	"fmt"
	"io"
	"sort"
)

// BaselineDiffKind describes what changed between two baselines.
type BaselineDiffKind string

const (
	BaselineAdded   BaselineDiffKind = "added"
	BaselineRemoved BaselineDiffKind = "removed"
	BaselineChanged BaselineDiffKind = "changed"
)

// BaselineDiffEntry records a single change between two baselines.
type BaselineDiffEntry struct {
	Path string           `json:"path"`
	Kind BaselineDiffKind `json:"kind"`
	Old  *Secret          `json:"old,omitempty"`
	New  *Secret          `json:"new,omitempty"`
}

// DiffBaselines compares an old and new Baseline and returns the list of changes.
func DiffBaselines(old, current *Baseline) []BaselineDiffEntry {
	var entries []BaselineDiffEntry

	for path, newSec := range current.Secrets {
		if oldSec, ok := old.Secrets[path]; !ok {
			n := newSec
			entries = append(entries, BaselineDiffEntry{Path: path, Kind: BaselineAdded, New: &n})
		} else if oldSec.Value != newSec.Value {
			o, n := oldSec, newSec
			entries = append(entries, BaselineDiffEntry{Path: path, Kind: BaselineChanged, Old: &o, New: &n})
		}
	}

	for path, oldSec := range old.Secrets {
		if _, ok := current.Secrets[path]; !ok {
			o := oldSec
			entries = append(entries, BaselineDiffEntry{Path: path, Kind: BaselineRemoved, Old: &o})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
	return entries
}

// WriteBaselineDiff writes a human-readable diff to w.
func WriteBaselineDiff(w io.Writer, entries []BaselineDiffEntry) {
	if len(entries) == 0 {
		fmt.Fprintln(w, "No changes detected since baseline.")
		return
	}
	for _, e := range entries {
		switch e.Kind {
		case BaselineAdded:
			fmt.Fprintf(w, "[+] %s (added)\n", e.Path)
		case BaselineRemoved:
			fmt.Fprintf(w, "[-] %s (removed)\n", e.Path)
		case BaselineChanged:
			fmt.Fprintf(w, "[~] %s (changed)\n", e.Path)
		}
	}
}
