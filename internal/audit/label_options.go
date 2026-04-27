package audit

// LabelOptions configures how the Labeler is built from CLI or config inputs.
type LabelOptions struct {
	// Rules is a list of prefix-to-labels mappings.
	Rules []LabelRule
}

// DefaultLabelOptions returns a LabelOptions with no rules.
func DefaultLabelOptions() LabelOptions {
	return LabelOptions{}
}

// AddRule appends a rule to the options. Empty prefixes or empty label maps
// are ignored.
func (o *LabelOptions) AddRule(prefix string, labels map[string]string) {
	if prefix == "" || len(labels) == 0 {
		return
	}
	o.Rules = append(o.Rules, LabelRule{Prefix: prefix, Labels: labels})
}

// BuildLabeler constructs a Labeler from the options.
func (o LabelOptions) BuildLabeler() *Labeler {
	l := NewLabeler()
	for _, r := range o.Rules {
		l.AddRule(r.Prefix, r.Labels)
	}
	return l
}
