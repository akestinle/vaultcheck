package audit

import "strings"

// TransformFunc is a function that transforms a single Secret.
type TransformFunc func(s Secret) Secret

// Transformer applies a pipeline of TransformFuncs to a slice of secrets.
type Transformer struct {
	funcs []TransformFunc
}

// NewTransformer returns a new Transformer with no transform functions.
func NewTransformer() *Transformer {
	return &Transformer{}
}

// Add appends a TransformFunc to the pipeline.
// If fn is nil it is silently ignored.
func (t *Transformer) Add(fn TransformFunc) {
	if fn == nil {
		return
	}
	t.funcs = append(t.funcs, fn)
}

// Transform applies every registered TransformFunc to each secret in order
// and returns the resulting slice.
func (t *Transformer) Transform(secrets []Secret) []Secret {
	out := make([]Secret, len(secrets))
	for i, s := range secrets {
		for _, fn := range t.funcs {
			s = fn(s)
		}
		out[i] = s
	}
	return out
}

// NormalizePathTransform returns a TransformFunc that lower-cases the secret
// path and trims leading/trailing slashes.
func NormalizePathTransform() TransformFunc {
	return func(s Secret) Secret {
		s.Path = strings.ToLower(strings.Trim(s.Path, "/"))
		return s
	}
}

// SetOwnerTransform returns a TransformFunc that sets the owner field to
// defaultOwner when the secret has no owner assigned.
func SetOwnerTransform(defaultOwner string) TransformFunc {
	return func(s Secret) Secret {
		if s.Owner == "" {
			s.Owner = defaultOwner
		}
		return s
	}
}

// RedactValueTransform returns a TransformFunc that replaces the secret value
// with a fixed redaction placeholder so it is safe for logging/export.
func RedactValueTransform(placeholder string) TransformFunc {
	if placeholder == "" {
		placeholder = "***REDACTED***"
	}
	return func(s Secret) Secret {
		s.Value = placeholder
		return s
	}
}
