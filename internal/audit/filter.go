package audit

import (
	"regexp"
	"strings"
	"time"
)

// FilterOptions controls which secrets are included in a filtered result.
type FilterOptions struct {
	PathPrefix string
	KeyPattern string
	MaxAgeDays int
	ExcludePaths []string
}

// Filter applies FilterOptions to a slice of SecretMeta and returns matching entries.
func Filter(secrets []SecretMeta, opts FilterOptions) ([]SecretMeta, error) {
	var keyRe *regexp.Regexp
	if opts.KeyPattern != "" {
		var err error
		keyRe, err = regexp.Compile(opts.KeyPattern)
		if err != nil {
			return nil, err
		}
	}

	excludeSet := make(map[string]struct{}, len(opts.ExcludePaths))
	for _, p := range opts.ExcludePaths {
		excludeSet[p] = struct{}{}
	}

	var result []SecretMeta
	for _, s := range secrets {
		if _, excluded := excludeSet[s.Path]; excluded {
			continue
		}
		if opts.PathPrefix != "" && !strings.HasPrefix(s.Path, opts.PathPrefix) {
			continue
		}
		if keyRe != nil && !keyRe.MatchString(s.Key) {
			continue
		}
		if opts.MaxAgeDays > 0 && !s.UpdatedAt.IsZero() {
			cutoff := time.Now().AddDate(0, 0, -opts.MaxAgeDays)
			if s.UpdatedAt.Before(cutoff) {
				continue
			}
		}
		result = append(result, s)
	}
	return result, nil
}
