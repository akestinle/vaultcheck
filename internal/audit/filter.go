package audit

import (
	"path"
	"regexp"
	"strings"
	"time"
)

// FilterOptions controls which secrets are included in a scan result.
type FilterOptions struct {
	PathPrefix  string
	KeyPattern  string
	MaxAgeDays  int
	ExcludePaths []string
}

// Filter applies FilterOptions to a slice of SecretMeta and returns only
// the entries that satisfy all configured criteria.
func Filter(secrets []SecretMeta, opts FilterOptions) ([]SecretMeta, error) {
	var re *regexp.Regexp
	if opts.KeyPattern != "" {
		var err error
		re, err = regexp.Compile(opts.KeyPattern)
		if err != nil {
			return nil, err
		}
	}

	cutoff := time.Time{}
	if opts.MaxAgeDays > 0 {
		cutoff = time.Now().UTC().AddDate(0, 0, -opts.MaxAgeDays)
	}

	var out []SecretMeta
	for _, s := range secrets {
		if !matchPrefix(s.Path, opts.PathPrefix) {
			continue
		}
		if isExcluded(s.Path, opts.ExcludePaths) {
			continue
		}
		if re != nil && !re.MatchString(s.Key) {
			continue
		}
		if !cutoff.IsZero() && !s.UpdatedAt.IsZero() && s.UpdatedAt.Before(cutoff) {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func matchPrefix(p, prefix string) bool {
	if prefix == "" {
		return true
	}
	return strings.HasPrefix(p, prefix)
}

func isExcluded(p string, excludes []string) bool {
	for _, pattern := range excludes {
		if matched, _ := path.Match(pattern, p); matched {
			return true
		}
		if strings.HasPrefix(p, pattern) {
			return true
		}
	}
	return false
}
