package audit

import "time"

// ScanOptions controls the behaviour of a single Scanner.Scan call.
type ScanOptions struct {
	// PathPrefix restricts scanning to secrets whose path starts with this value.
	PathPrefix string

	// KeyPattern is a regex applied to secret key names; empty means all keys.
	KeyPattern string

	// MaxAgeDays excludes secrets last updated more than this many days ago.
	// A value of 0 disables the age filter.
	MaxAgeDays int

	// ExcludePaths is a list of exact paths to skip during the scan.
	ExcludePaths []string

	// AsOf allows the caller to fix the reference time used for age
	// calculations. When zero, time.Now() is used.
	AsOf time.Time
}

// effectiveAsOf returns AsOf if set, otherwise the current time.
func (o ScanOptions) effectiveAsOf() time.Time {
	if o.AsOf.IsZero() {
		return time.Now()
	}
	return o.AsOf
}

// toFilterOptions converts ScanOptions into the FilterOptions used by Filter.
func (o ScanOptions) toFilterOptions() FilterOptions {
	return FilterOptions{
		PathPrefix:   o.PathPrefix,
		KeyPattern:   o.KeyPattern,
		MaxAgeDays:   o.MaxAgeDays,
		ExcludePaths: o.ExcludePaths,
		AsOf:         o.effectiveAsOf(),
	}
}

// IsExcluded reports whether the given path should be skipped according to
// the ExcludePaths list.
func (o ScanOptions) IsExcluded(path string) bool {
	for _, excluded := range o.ExcludePaths {
		if excluded == path {
			return true
		}
	}
	return false
}
