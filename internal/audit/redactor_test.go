package audit

import (
	"regexp"
	"testing"
	"time"
)

func redactorSecrets() []Secret {
	now := time.Now()
	return []Secret{
		{Path: "secret/db/password", Key: "password", Value: "supersecret123", CreatedAt: now},
		{Path: "secret/api/key", Key: "api_key", Value: "tok_abcdef", CreatedAt: now},
		{Path: "secret/plain", Key: "note", Value: "not-sensitive", CreatedAt: now},
	}
}

func TestNewRedactor_DefaultMask(t *testing.T) {
	r := NewRedactor(DefaultRedactOptions())
	if r == nil {
		t.Fatal("expected non-nil redactor")
	}
}

func TestRedactor_Mask_AllValues(t *testing.T) {
	r := NewRedactor(DefaultRedactOptions())
	out := r.Redact(redactorSecrets())
	for _, s := range out {
		if s.Value != "[REDACTED]" {
			t.Errorf("path %s: expected [REDACTED], got %q", s.Path, s.Value)
		}
	}
}

func TestRedactor_DoesNotMutateOriginal(t *testing.T) {
	originals := redactorSecrets()
	r := NewRedactor(DefaultRedactOptions())
	r.Redact(originals)
	for _, s := range originals {
		if s.Value == "[REDACTED]" {
			t.Errorf("original secret at %s was mutated", s.Path)
		}
	}
}

func TestRedactor_BlankMode(t *testing.T) {
	r := NewRedactor(RedactOptions{Mode: RedactBlank})
	out := r.Redact(redactorSecrets())
	for _, s := range out {
		if s.Value != "" {
			t.Errorf("expected blank, got %q", s.Value)
		}
	}
}

func TestRedactor_HashMode(t *testing.T) {
	r := NewRedactor(RedactOptions{Mode: RedactHash})
	out := r.Redact(redactorSecrets())
	for _, s := range out {
		if s.Value == "" {
			t.Errorf("hash hint should not be empty for path %s", s.Path)
		}
		if len(s.Value) < 3 {
			t.Errorf("hash hint too short for path %s: %q", s.Path, s.Value)
		}
	}
}

func TestRedactor_PatternFilter_OnlyMatchingRedacted(t *testing.T) {
	pat := regexp.MustCompile(`^tok_`)
	r := NewRedactor(RedactOptions{Mode: RedactMask, Mask: "[REDACTED]", Pattern: pat})
	out := r.Redact(redactorSecrets())

	for _, s := range out {
		if s.Key == "api_key" && s.Value != "[REDACTED]" {
			t.Errorf("api_key should be redacted, got %q", s.Value)
		}
		if s.Key == "password" && s.Value == "[REDACTED]" {
			t.Errorf("password should NOT be redacted by tok_ pattern")
		}
	}
}

func TestRedactor_EmptySlice(t *testing.T) {
	r := NewRedactor(DefaultRedactOptions())
	out := r.Redact([]Secret{})
	if len(out) != 0 {
		t.Errorf("expected empty slice, got %d", len(out))
	}
}
