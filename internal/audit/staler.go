package audit

import "time"

// StalenessOptions controls how secrets are classified as stale.
type StalenessOptions struct {
	// WarnAfterDays marks a secret as stale-warn when it hasn't been rotated
	// within this many days. Defaults to 90.
	WarnAfterDays int
	// CriticalAfterDays marks a secret as stale-critical. Defaults to 180.
	CriticalAfterDays int
	// AsOf is the reference time; zero means time.Now().
	AsOf time.Time
}

// StalenessLevel represents how stale a secret is.
type StalenessLevel string

const (
	StalenessOK       StalenessLevel = "ok"
	StalenessWarn     StalenessLevel = "warn"
	StalenessCritical StalenessLevel = "critical"
)

// StalenessResult holds the classification for a single secret.
type StalenessResult struct {
	Secret Secret
	Level  StalenessLevel
	AgeDays int
}

// Staler classifies secrets by how long they have gone without rotation.
type Staler struct {
	opts StalenessOptions
}

// NewStaler creates a Staler with the given options, applying defaults where
// values are zero.
func NewStaler(opts StalenessOptions) *Staler {
	if opts.WarnAfterDays <= 0 {
		opts.WarnAfterDays = 90
	}
	if opts.CriticalAfterDays <= 0 {
		opts.CriticalAfterDays = 180
	}
	if opts.AsOf.IsZero() {
		opts.AsOf = time.Now()
	}
	return &Staler{opts: opts}
}

// Classify returns a StalenessResult for a single secret.
func (s *Staler) Classify(sec Secret) StalenessResult {
	age := int(s.opts.AsOf.Sub(sec.CreatedAt).Hours() / 24)
	if age < 0 {
		age = 0
	}
	level := StalenessOK
	switch {
	case age >= s.opts.CriticalAfterDays:
		level = StalenessCritical
	case age >= s.opts.WarnAfterDays:
		level = StalenessWarn
	}
	return StalenessResult{Secret: sec, Level: level, AgeDays: age}
}

// ClassifyAll classifies every secret in the slice and returns all results.
func (s *Staler) ClassifyAll(secrets []Secret) []StalenessResult {
	out := make([]StalenessResult, 0, len(secrets))
	for _, sec := range secrets {
		out = append(out, s.Classify(sec))
	}
	return out
}

// Filter returns only results whose level is at least minLevel.
func Filter(results []StalenessResult, minLevel StalenessLevel) []StalenessResult {
	rank := map[StalenessLevel]int{
		StalenessOK: 0, StalenessWarn: 1, StalenessCritical: 2,
	}
	min := rank[minLevel]
	out := results[:0:0]
	for _, r := range results {
		if rank[r.Level] >= min {
			out = append(out, r)
		}
	}
	return out
}
