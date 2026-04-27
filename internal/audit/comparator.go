package audit

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
)

// CompareResult holds the outcome of comparing two secret slices.
type CompareResult struct {
	Added   []Secret
	Removed []Secret
	Changed []Secret
	Unchanged []Secret
}

// TotalDelta returns the net number of secrets added minus removed.
func (r *CompareResult) TotalDelta() int {
	return len(r.Added) - len(r.Removed)
}

// HasChanges returns true when any additions, removals, or modifications exist.
func (r *CompareResult) HasChanges() bool {
	return len(r.Added) > 0 || len(r.Removed) > 0 || len(r.Changed) > 0
}

// Compare diffs two slices of secrets by path, returning a CompareResult.
func Compare(before, after []Secret) *CompareResult {
	result := &CompareResult{}

	beforeMap := make(map[string]Secret, len(before))
	for _, s := range before {
		beforeMap[s.Path] = s
	}

	afterMap := make(map[string]Secret, len(after))
	for _, s := range after {
		afterMap[s.Path] = s
	}

	for _, s := range after {
		if old, ok := beforeMap[s.Path]; !ok {
			result.Added = append(result.Added, s)
		} else if old.Value != s.Value {
			result.Changed = append(result.Changed, s)
		} else {
			result.Unchanged = append(result.Unchanged, s)
		}
	}

	for _, s := range before {
		if _, ok := afterMap[s.Path]; !ok {
			result.Removed = append(result.Removed, s)
		}
	}

	sortByPath := func(sl []Secret) {
		sort.Slice(sl, func(i, j int) bool { return sl[i].Path < sl[j].Path })
	}
	sortByPath(result.Added)
	sortByPath(result.Removed)
	sortByPath(result.Changed)
	sortByPath(result.Unchanged)

	return result
}

// WriteCompareResult writes a human-readable diff table to w.
func WriteCompareResult(w io.Writer, r *CompareResult) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tPATH")
	for _, s := range r.Added {
		fmt.Fprintf(tw, "+ added\t%s\n", s.Path)
	}
	for _, s := range r.Removed {
		fmt.Fprintf(tw, "- removed\t%s\n", s.Path)
	}
	for _, s := range r.Changed {
		fmt.Fprintf(tw, "~ changed\t%s\n", s.Path)
	}
	if !r.HasChanges() {
		fmt.Fprintln(tw, "(no changes)")
	}
	return tw.Flush()
}
