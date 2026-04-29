package audit

import (
	"regexp"
	"strings"
)

// RedactMode controls how secret values are redacted.
type RedactMode int

const (
	RedactMask  RedactMode = iota // Replace with fixed mask string
	RedactHash                    // Replace with partial hash hint
	RedactBlank                   // Replace with empty string
)

// RedactOptions configures the Redactor.
type RedactOptions struct {
	Mode    RedactMode
	Mask    string
	Pattern *regexp.Regexp // if set, only redact values matching this pattern
}

// DefaultRedactOptions returns sensible defaults.
func DefaultRedactOptions() RedactOptions {
	return RedactOptions{
		Mode: RedactMask,
		Mask: "[REDACTED]",
	}
}

// Redactor masks secret values in a slice of Secret.
type Redactor struct {
	opts RedactOptions
}

// NewRedactor creates a Redactor with the given options.
func NewRedactor(opts RedactOptions) *Redactor {
	if opts.Mask == "" {
		opts.Mask = "[REDACTED]"
	}
	return &Redactor{opts: opts}
}

// Redact returns a new slice of secrets with values masked.
// Original secrets are not mutated.
func (r *Redactor) Redact(secrets []Secret) []Secret {
	out := make([]Secret, len(secrets))
	for i, s := range secrets {
		copy := s
		copy.Value = r.redactValue(s.Value)
		out[i] = copy
	}
	return out
}

func (r *Redactor) redactValue(v string) string {
	if r.opts.Pattern != nil && !r.opts.Pattern.MatchString(v) {
		return v
	}
	switch r.opts.Mode {
	case RedactBlank:
		return ""
	case RedactHash:
		return hashHint(v)
	default:
		return r.opts.Mask
	}
}

// hashHint returns a short non-reversible hint like "ab12****" to aid debugging.
func hashHint(v string) string {
	if len(v) <= 4 {
		return strings.Repeat("*", len(v))
	}
	return v[:2] + strings.Repeat("*", len(v)-2)
}
