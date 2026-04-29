package audit

import (
	"fmt"
	"io"
	"sort"
	"time"
)

// RetentionPolicy defines rules for how long secrets should be retained.
type RetentionPolicy struct {
	DefaultMaxAgeDays int
	PrefixOverrides   map[string]int // prefix -> max age in days
}

// RetentionResult holds the evaluation of a secret against a retention policy.
type RetentionResult struct {
	Secret     Secret
	MaxAgeDays int
	AgeDays    float64
	Violates   bool
}

// NewRetentionPolicy returns a RetentionPolicy with a default max age.
func NewRetentionPolicy(defaultMaxAgeDays int) *RetentionPolicy {
	if defaultMaxAgeDays <= 0 {
		defaultMaxAgeDays = 90
	}
	return &RetentionPolicy{
		DefaultMaxAgeDays: defaultMaxAgeDays,
		PrefixOverrides:   make(map[string]int),
	}
}

// AddPrefixOverride sets a custom max age for secrets matching the given path prefix.
func (p *RetentionPolicy) AddPrefixOverride(prefix string, maxAgeDays int) {
	if prefix == "" || maxAgeDays <= 0 {
		return
	}
	p.PrefixOverrides[prefix] = maxAgeDays
}

// Evaluate checks each secret against the retention policy and returns results.
func (p *RetentionPolicy) Evaluate(secrets []Secret) []RetentionResult {
	now := time.Now()
	results := make([]RetentionResult, 0, len(secrets))
	for _, s := range secrets {
		max := p.maxAgeFor(s.Path)
		age := now.Sub(s.CreatedAt).Hours() / 24
		results = append(results, RetentionResult{
			Secret:     s,
			MaxAgeDays: max,
			AgeDays:    age,
			Violates:   age > float64(max),
		})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Secret.Path < results[j].Secret.Path
	})
	return results
}

func (p *RetentionPolicy) maxAgeFor(path string) int {
	best, bestLen := p.DefaultMaxAgeDays, -1
	for prefix, days := range p.PrefixOverrides {
		if len(prefix) > bestLen && len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			best, bestLen = days, len(prefix)
		}
	}
	return best
}

// WriteRetentionReport writes a human-readable retention report to w.
func WriteRetentionReport(w io.Writer, results []RetentionResult) {
	violations := 0
	for _, r := range results {
		if r.Violates {
			violations++
		}
	}
	fmt.Fprintf(w, "Retention Report: %d secrets, %d violation(s)\n", len(results), violations)
	fmt.Fprintln(w, "---")
	for _, r := range results {
		status := "OK"
		if r.Violates {
			status = "VIOLATION"
		}
		fmt.Fprintf(w, "[%s] %s (age=%.1fd, max=%dd)\n", status, r.Secret.Path, r.AgeDays, r.MaxAgeDays)
	}
}
