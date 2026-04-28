package audit

import (
	"fmt"
	"testing"
	"time"
)

func validatorSecrets() []Secret {
	now := time.Now()
	return []Secret{
		{Path: "secret/db/password", Value: "s3cr3t", Owner: "team-db", CreatedAt: now},
		{Path: "secret/api/key", Value: "apikey123", Owner: "", CreatedAt: now},
		{Path: "", Value: "orphan", Owner: "team-x", CreatedAt: now},
		{Path: "secret/empty/val", Value: "", Owner: "team-y", CreatedAt: now},
	}
}

func TestNewValidator_NotNil(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("expected non-nil validator")
	}
}

func TestValidate_ValidSecret_NoErrors(t *testing.T) {
	v := NewValidator()
	results := v.Validate(validatorSecrets()[:1])
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].IsValid() {
		t.Errorf("expected valid secret, got errors: %v", results[0].Errors)
	}
}

func TestValidate_MissingOwner(t *testing.T) {
	v := NewValidator()
	secrets := validatorSecrets()[1:2] // no owner
	results := v.Validate(secrets)
	if results[0].IsValid() {
		t.Error("expected validation error for missing owner")
	}
	found := false
	for _, e := range results[0].Errors {
		if contains(e, "has-owner") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected has-owner error, got: %v", results[0].Errors)
	}
}

func TestValidate_EmptyPath(t *testing.T) {
	v := NewValidator()
	results := v.Validate(validatorSecrets()[2:3])
	if results[0].IsValid() {
		t.Error("expected validation error for empty path")
	}
}

func TestValidate_EmptyValue(t *testing.T) {
	v := NewValidator()
	results := v.Validate(validatorSecrets()[3:4])
	if results[0].IsValid() {
		t.Error("expected validation error for empty value")
	}
}

func TestValidator_AddRule_Custom(t *testing.T) {
	v := NewValidator()
	v.AddRule(ValidationRule{
		Name: "min-length",
		Check: func(s Secret) error {
			if len(s.Value) < 10 {
				return fmt.Errorf("value too short at %q", s.Path)
			}
			return nil
		},
	})
	secrets := validatorSecrets()[:1] // value "s3cr3t" len=6
	results := v.Validate(secrets)
	if results[0].IsValid() {
		t.Error("expected custom rule to flag short value")
	}
}

func TestValidator_AddRule_EmptyNameIgnored(t *testing.T) {
	v := NewValidator()
	before := len(v.rules)
	v.AddRule(ValidationRule{Name: "", Check: func(s Secret) error { return nil }})
	if len(v.rules) != before {
		t.Error("expected rule with empty name to be ignored")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})())
}
