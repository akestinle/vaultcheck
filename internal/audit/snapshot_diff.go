package audit

import (
	"fmt"
	"io"
)

// SnapshotDiffResult holds the changes between two snapshots.
type SnapshotDiffResult struct {
	Added   []Secret
	Removed []Secret
	Changed []Secret
}

// DiffSnapshots compares two snapshots and returns what changed between them.
func DiffSnapshots(before, after *Snapshot) SnapshotDiffResult {
	result := SnapshotDiffResult{}

	beforeIndex := make(map[string]Secret, len(before.Secrets))
	for _, s := range before.Secrets {
		beforeIndex[s.Path+":"+s.Key] = s
	}

	afterIndex := make(map[string]Secret, len(after.Secrets))
	for _, s := range after.Secrets {
		afterIndex[s.Path+":"+s.Key] = s
	}

	for k, a := range afterIndex {
		if b, ok := beforeIndex[k]; !ok {
			result.Added = append(result.Added, a)
		} else if b.Value != a.Value {
			result.Changed = append(result.Changed, a)
		}
	}

	for k, b := range beforeIndex {
		if _, ok := afterIndex[k]; !ok {
			result.Removed = append(result.Removed, b)
		}
	}

	return result
}

// WriteSnapshotDiff writes a human-readable diff of two snapshots to w.
func WriteSnapshotDiff(w io.Writer, before, after *Snapshot, result SnapshotDiffResult) {
	fmt.Fprintf(w, "Snapshot diff: %s → %s\n", before.ID, after.ID)
	fmt.Fprintf(w, "  Added:   %d\n", len(result.Added))
	fmt.Fprintf(w, "  Removed: %d\n", len(result.Removed))
	fmt.Fprintf(w, "  Changed: %d\n", len(result.Changed))
	if len(result.Added) > 0 {
		fmt.Fprintln(w, "\n+ Added:")
		for _, s := range result.Added {
			fmt.Fprintf(w, "    + %s/%s\n", s.Path, s.Key)
		}
	}
	if len(result.Removed) > 0 {
		fmt.Fprintln(w, "\n- Removed:")
		for _, s := range result.Removed {
			fmt.Fprintf(w, "    - %s/%s\n", s.Path, s.Key)
		}
	}
	if len(result.Changed) > 0 {
		fmt.Fprintln(w, "\n~ Changed:")
		for _, s := range result.Changed {
			fmt.Fprintf(w, "    ~ %s/%s\n", s.Path, s.Key)
		}
	}
}
