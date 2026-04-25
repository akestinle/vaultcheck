package audit

import (
	"fmt"
	"io"
	"sort"
	"time"
)

// Summary holds aggregated statistics for a set of scanned secrets.
type Summary struct {
	TotalSecrets   int
	ExpiredSecrets int
	ExpiringIn30   int
	OldestSecret   *Secret
	NewestSecret   *Secret
	PathCounts     map[string]int
	GeneratedAt    time.Time
}

// NewSummary builds a Summary from a slice of secrets.
func NewSummary(secrets []Secret) *Summary {
	s := &Summary{
		PathCounts:  make(map[string]int),
		GeneratedAt: time.Now().UTC(),
	}

	now := time.Now().UTC()
	thirty := now.Add(30 * 24 * time.Hour)

	for i := range secrets {
		sec := &secrets[i]
		s.TotalSecrets++

		if sec.IsExpired() {
			s.ExpiredSecrets++
		} else if sec.ExpiresAt != nil && sec.ExpiresAt.Before(thirty) {
			s.ExpiringIn30++
		}

		// track oldest / newest by UpdatedAt
		if s.OldestSecret == nil || sec.UpdatedAt.Before(s.OldestSecret.UpdatedAt) {
			s.OldestSecret = sec
		}
		if s.NewestSecret == nil || sec.UpdatedAt.After(s.NewestSecret.UpdatedAt) {
			s.NewestSecret = sec
		}

		// count by top-level path segment
		segment := topLevelSegment(sec.Path)
		s.PathCounts[segment]++
	}

	return s
}

// WriteSummary writes a human-readable summary to w.
func (s *Summary) WriteSummary(w io.Writer) error {
	fmt.Fprintf(w, "Audit Summary — %s\n", s.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "  Total secrets  : %d\n", s.TotalSecrets)
	fmt.Fprintf(w, "  Expired        : %d\n", s.ExpiredSecrets)
	fmt.Fprintf(w, "  Expiring ≤30d  : %d\n", s.ExpiringIn30)

	if s.OldestSecret != nil {
		fmt.Fprintf(w, "  Oldest secret  : %s (%s)\n", s.OldestSecret.Path, s.OldestSecret.UpdatedAt.Format("2006-01-02"))
	}
	if s.NewestSecret != nil {
		fmt.Fprintf(w, "  Newest secret  : %s (%s)\n", s.NewestSecret.Path, s.NewestSecret.UpdatedAt.Format("2006-01-02"))
	}

	if len(s.PathCounts) > 0 {
		fmt.Fprintln(w, "  Top-level paths:")
		keys := make([]string, 0, len(s.PathCounts))
		for k := range s.PathCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "    %-30s %d\n", k, s.PathCounts[k])
		}
	}
	return nil
}

// topLevelSegment returns the first path component of p.
func topLevelSegment(p string) string {
	for i, c := range p {
		if i > 0 && c == '/' {
			return p[:i]
		}
	}
	return p
}
