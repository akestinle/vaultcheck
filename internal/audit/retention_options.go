package audit

// RetentionOptions configures a RetentionPolicy from structured input.
type RetentionOptions struct {
	DefaultMaxAgeDays int
	PrefixRules       []RetentionPrefixRule
}

// RetentionPrefixRule maps a path prefix to a custom max age.
type RetentionPrefixRule struct {
	Prefix     string
	MaxAgeDays int
}

// DefaultRetentionOptions returns sensible defaults.
func DefaultRetentionOptions() RetentionOptions {
	return RetentionOptions{
		DefaultMaxAgeDays: 90,
	}
}

// AddRule appends a prefix rule, ignoring invalid entries.
func (o *RetentionOptions) AddRule(prefix string, maxAgeDays int) {
	if prefix == "" || maxAgeDays <= 0 {
		return
	}
	o.PrefixRules = append(o.PrefixRules, RetentionPrefixRule{
		Prefix:     prefix,
		MaxAgeDays: maxAgeDays,
	})
}

// BuildPolicy constructs a RetentionPolicy from the options.
func (o RetentionOptions) BuildPolicy() *RetentionPolicy {
	p := NewRetentionPolicy(o.DefaultMaxAgeDays)
	for _, r := range o.PrefixRules {
		p.AddPrefixOverride(r.Prefix, r.MaxAgeDays)
	}
	return p
}
