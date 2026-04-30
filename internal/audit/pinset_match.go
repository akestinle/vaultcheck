package audit

import "sort"

// PinsetMatchResult holds the outcome of matching secrets against a pinset.
type PinsetMatchResult struct {
	Name      string
	Matched   []Secret
	Unmatched []Secret
}

// MatchPinset returns secrets whose paths are in the named pinset and those
// that are not, without modifying the original slice.
func MatchPinset(ps *Pinset, name string, secrets []Secret) PinsetMatchResult {
	res := PinsetMatchResult{Name: name}
	for _, s := range secrets {
		if ps.Contains(name, s.Path) {
			res.Matched = append(res.Matched, s)
		} else {
			res.Unmatched = append(res.Unmatched, s)
		}
	}
	sort.Slice(res.Matched, func(i, j int) bool {
		return res.Matched[i].Path < res.Matched[j].Path
	})
	sort.Slice(res.Unmatched, func(i, j int) bool {
		return res.Unmatched[i].Path < res.Unmatched[j].Path
	})
	return res
}

// FilterByPinset returns only the secrets whose paths appear in the named
// pinset.
func FilterByPinset(ps *Pinset, name string, secrets []Secret) []Secret {
	return MatchPinset(ps, name, secrets).Matched
}
