package audit

import (
	"math/rand"
	"sort"
)

// SampleMode controls how secrets are selected during sampling.
type SampleMode int

const (
	// SampleRandom selects secrets randomly.
	SampleRandom SampleMode = iota
	// SampleFirst selects the first N secrets by path order.
	SampleFirst
	// SampleLast selects the last N secrets by path order.
	SampleLast
)

// SampleOptions configures sampling behaviour.
type SampleOptions struct {
	N    int
	Mode SampleMode
	Seed int64
}

// DefaultSampleOptions returns sensible defaults.
func DefaultSampleOptions() SampleOptions {
	return SampleOptions{
		N:    10,
		Mode: SampleRandom,
		Seed: 42,
	}
}

// Sampler draws a subset of secrets from a larger collection.
type Sampler struct {
	opts SampleOptions
}

// NewSampler creates a Sampler with the given options.
// N is clamped to 1 if non-positive.
func NewSampler(opts SampleOptions) *Sampler {
	if opts.N <= 0 {
		opts.N = 1
	}
	return &Sampler{opts: opts}
}

// Sample returns up to N secrets from secrets according to the configured mode.
func (s *Sampler) Sample(secrets []Secret) []Secret {
	if len(secrets) == 0 {
		return []Secret{}
	}

	// Work on a shallow copy to avoid mutating the caller's slice.
	pool := make([]Secret, len(secrets))
	copy(pool, secrets)

	switch s.opts.Mode {
	case SampleFirst:
		sort.Slice(pool, func(i, j int) bool {
			return pool[i].Path < pool[j].Path
		})
		return capped(pool, s.opts.N)

	case SampleLast:
		sort.Slice(pool, func(i, j int) bool {
			return pool[i].Path > pool[j].Path
		})
		return capped(pool, s.opts.N)

	default: // SampleRandom
		r := rand.New(rand.NewSource(s.opts.Seed)) //nolint:gosec
		r.Shuffle(len(pool), func(i, j int) {
			pool[i], pool[j] = pool[j], pool[i]
		})
		return capped(pool, s.opts.N)
	}
}

func capped(s []Secret, n int) []Secret {
	if n >= len(s) {
		return s
	}
	return s[:n]
}
