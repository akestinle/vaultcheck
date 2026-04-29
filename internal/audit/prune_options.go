package audit

// DefaultPruneOptions returns a PruneOptions with sensible defaults.
func DefaultPruneOptions() PruneOptions {
	return PruneOptions{
		MaxAgeDays:   90,
		DryRun:       false,
		PathPrefixes: nil,
	}
}

// PruneOptionsBuilder provides a fluent API for constructing PruneOptions.
type PruneOptionsBuilder struct {
	opts PruneOptions
}

// NewPruneOptionsBuilder creates a builder seeded with defaults.
func NewPruneOptionsBuilder() *PruneOptionsBuilder {
	return &PruneOptionsBuilder{opts: DefaultPruneOptions()}
}

// WithMaxAgeDays sets the maximum age threshold in days.
func (b *PruneOptionsBuilder) WithMaxAgeDays(days int) *PruneOptionsBuilder {
	if days > 0 {
		b.opts.MaxAgeDays = days
	}
	return b
}

// WithDryRun enables dry-run mode.
func (b *PruneOptionsBuilder) WithDryRun(v bool) *PruneOptionsBuilder {
	b.opts.DryRun = v
	return b
}

// WithPathPrefix appends a path prefix constraint.
func (b *PruneOptionsBuilder) WithPathPrefix(prefix string) *PruneOptionsBuilder {
	if prefix != "" {
		b.opts.PathPrefixes = append(b.opts.PathPrefixes, prefix)
	}
	return b
}

// Build returns the constructed PruneOptions.
func (b *PruneOptionsBuilder) Build() PruneOptions {
	return b.opts
}
