package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

var retentionSecrets = []Secret{
	{
		Path:      "secret/old/token",
		CreatedAt: time.Now().AddDate(0, 0, -120),
	},
	{
		Path:      "secret/fresh/api",
		CreatedAt: time.Now().AddDate(0, 0, -10),
	},
	{
		Path:      "secret/db/password",
		CreatedAt: time.Now().AddDate(0, 0, -45),
	},
}

func TestNewRetentionPolicy_Defaults(t *testing.T) {
	p := NewRetentionPolicy(0)
	if p.DefaultMaxAgeDays != 90 {
		t.Errorf("expected default 90, got %d", p.DefaultMaxAgeDays)
	}
}

func TestNewRetentionPolicy_CustomDefault(t *testing.T) {
	p := NewRetentionPolicy(60)
	if p.DefaultMaxAgeDays != 60 {
		t.Errorf("expected 60, got %d", p.DefaultMaxAgeDays)
	}
}

func TestRetentionPolicy_Evaluate_Violation(t *testing.T) {
	p := NewRetentionPolicy(90)
	results := p.Evaluate(retentionSecrets)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	// secret/old/token is 120 days old, should violate
	var found bool
	for _, r := range results {
		if r.Secret.Path == "secret/old/token" {
			found = true
			if !r.Violates {
				t.Error("expected violation for old token")
			}
		}
	}
	if !found {
		t.Error("old token not found in results")
	}
}

func TestRetentionPolicy_Evaluate_NoViolation(t *testing.T) {
	p := NewRetentionPolicy(90)
	results := p.Evaluate(retentionSecrets)
	for _, r := range results {
		if r.Secret.Path == "secret/fresh/api" && r.Violates {
			t.Error("fresh secret should not violate")
		}
	}
}

func TestRetentionPolicy_PrefixOverride(t *testing.T) {
	p := NewRetentionPolicy(90)
	p.AddPrefixOverride("secret/db", 30)
	results := p.Evaluate(retentionSecrets)
	for _, r := range results {
		if r.Secret.Path == "secret/db/password" {
			if r.MaxAgeDays != 30 {
				t.Errorf("expected max 30 for db prefix, got %d", r.MaxAgeDays)
			}
			if !r.Violates {
				t.Error("expected db/password to violate with 30-day limit")
			}
		}
	}
}

func TestRetentionPolicy_AddPrefixOverride_Invalid(t *testing.T) {
	p := NewRetentionPolicy(90)
	p.AddPrefixOverride("", 30)
	p.AddPrefixOverride("secret/x", 0)
	if len(p.PrefixOverrides) != 0 {
		t.Error("invalid overrides should be ignored")
	}
}

func TestWriteRetentionReport_ContainsViolation(t *testing.T) {
	p := NewRetentionPolicy(90)
	results := p.Evaluate(retentionSecrets)
	var buf bytes.Buffer
	WriteRetentionReport(&buf, results)
	out := buf.String()
	if !strings.Contains(out, "VIOLATION") {
		t.Error("expected VIOLATION in report output")
	}
	if !strings.Contains(out, "Retention Report") {
		t.Error("expected header in report output")
	}
}
