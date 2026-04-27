package audit

import "sort"

// MergeOptions controls how two secret slices are merged.
type MergeOptions struct {
	// PreferLeft keeps the left-side secret when both sides share a path.
	PreferLeft bool
}

// DefaultMergeOptions returns sensible defaults (prefer right/newer values).
func DefaultMergeOptions() MergeOptions {
	return MergeOptions{PreferLeft: false}
}

// Merger combines two collections of secrets into one deduplicated slice.
type Merger struct {
	opts MergeOptions
}

// NewMerger constructs a Merger with the supplied options.
func NewMerger(opts MergeOptions) *Merger {
	return &Merger{opts: opts}
}

// Merge combines left and right slices. When both sides contain a secret with
// the same Path the winner is chosen according to MergeOptions.PreferLeft.
// The returned slice is sorted by Path.
func (m *Merger) Merge(left, right []Secret) []Secret {
	index := make(map[string]Secret, len(left)+len(right))

	// Insert in the order that means the *last* write wins for the
	// non-preferred side, then overwrite with the preferred side.
	first, second := right, left
	if m.opts.PreferLeft {
		first, second = left, right
	}

	for _, s := range first {
		index[s.Path] = s
	}
	for _, s := range second {
		index[s.Path] = s
	}

	result := make([]Secret, 0, len(index))
	for _, s := range index {
		result = append(result, s)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Path < result[j].Path
	})

	return result
}
