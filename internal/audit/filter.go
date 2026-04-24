package audit

import (
	"strings"
	"time"
)

// FilterOptions controls which secrets are included in an audit scan.
type FilterOptions struct {
	// PathPrefix limits results to secrets whose path starts with this prefix.
	PathPrefix string

	// MaxAgeDays excludes secrets that were last updated within this many days.
	// A value of 0 disables age filtering.
	MaxAgeDays int

	// KeyPattern limits results to secrets whose key contains this substring.
	KeyPattern string
}

// Filter applies FilterOptions to a slice of SecretMeta and returns only
// the entries that satisfy all active criteria.
func Filter(secrets []SecretMeta, opts FilterOptions) []SecretMeta {
	var out []SecretMeta
	for _, s := range secrets {
		if opts.PathPrefix != "" && !strings.HasPrefix(s.Path, opts.PathPrefix) {
			continue
		}
		if opts.KeyPattern != "" && !strings.Contains(s.Key, opts.KeyPattern) {
			continue
		}
		if opts.MaxAgeDays > 0 && !s.LastUpdated.IsZero() {
			cutoff := time.Now().AddDate(0, 0, -opts.MaxAgeDays)
			if s.LastUpdated.After(cutoff) {
				continue
			}
		}
		out = append(out, s)
	}
	return out
}
