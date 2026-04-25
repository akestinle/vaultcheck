package audit

import (
	"path"
	"regexp"
	"time"
)

// FilterOptions controls which secrets are included in a scan result.
type FilterOptions struct {
	PathPrefix  string
	KeyPattern  string
	MaxAgeDays  int
	ExcludePaths []string
}

// Filter applies the given options to a slice of SecretMeta and returns
// only the entries that match all specified criteria.
func Filter(secrets []SecretMeta, opts FilterOptions) []SecretMeta {
	var out []SecretMeta

	var keyRe *regexp.Regexp
	if opts.KeyPattern != "" {
		keyRe = regexp.MustCompile(opts.KeyPattern)
	}

	for _, s := range secrets {
		if opts.PathPrefix != "" && !matchPrefix(s.Path, opts.PathPrefix) {
			continue
		}
		if isExcluded(s.Path, opts.ExcludePaths) {
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
		out = append(out, s)
	}
	return out
}

func matchPrefix(p, prefix string) bool {
	matched, err := path.Match(prefix+"*", p)
	if err != nil {
		return false
	}
	return matched
}

func isExcluded(p string, excludes []string) bool {
	for _, ex := range excludes {
		if ex == p {
			return true
		}
	}
	return false
}
