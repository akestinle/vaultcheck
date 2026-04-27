package audit

import "strings"

// LabelRule maps a path prefix to a set of key=value labels.
type LabelRule struct {
	Prefix string
	Labels map[string]string
}

// Labeler attaches metadata labels to secrets based on path prefix rules.
type Labeler struct {
	rules []LabelRule
}

// NewLabeler creates a new Labeler with no rules.
func NewLabeler() *Labeler {
	return &Labeler{}
}

// AddRule registers a labeling rule. Rules with empty prefixes or nil labels
// are silently ignored.
func (l *Labeler) AddRule(prefix string, labels map[string]string) {
	if prefix == "" || len(labels) == 0 {
		return
	}
	l.rules = append(l.rules, LabelRule{Prefix: prefix, Labels: labels})
}

// Label applies matching label rules to each secret, merging labels into the
// secret's existing metadata. Later rules take precedence over earlier ones.
func (l *Labeler) Label(secrets []Secret) []Secret {
	labeled := make([]Secret, len(secrets))
	for i, s := range secrets {
		merged := mergeLabels(s.Metadata)
		for _, rule := range l.rules {
			if strings.HasPrefix(s.Path, rule.Prefix) {
				for k, v := range rule.Labels {
					merged[k] = v
				}
			}
		}
		s.Metadata = merged
		labeled[i] = s
	}
	return labeled
}

func mergeLabels(existing map[string]string) map[string]string {
	out := make(map[string]string, len(existing))
	for k, v := range existing {
		out[k] = v
	}
	return out
}
