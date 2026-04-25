package audit

import (
	"regexp"
	"strings"
	"time"
)

// FilterOptions controls which secrets are included in audit results.
type FilterOptions struct {
	PathPrefix  string
	KeyPattern  string
	MaxAgeDays  int
	ExcludePaths []string
}

// Filter applies FilterOptions to a slice of SecretMeta, returning only matching entries.
func Filter(secrets []SecretMeta, opts FilterOptions) ([]SecretMeta, error) {
	var re *regexp.Regexp
	if opts.KeyPattern != "" {
		var err error
		re, err = regexp.Compile(opts.KeyPattern)
		if err != nil {
			return nil, err
		}
	}

	var out []SecretMeta
	for _, s := range secrets {
		if opts.PathPrefix != "" && !matchPrefix(s.Path, opts.PathPrefix) {
			continue
		}
		if isExcluded(s.Path, opts.ExcludePaths) {
			continue
		}
		if re != nil && !re.MatchString(s.Key) {
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
	return out, nil
}

func matchPrefix(path, prefix string) bool {
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return strings.HasPrefix(path, prefix) || path == strings.TrimSuffix(prefix, "/")
}

func isExcluded(path string, excludes []string) bool {
	for _, ex := range excludes {
		if matchPrefix(path, ex) || path == ex {
			return true
		}
	}
	return false
}
