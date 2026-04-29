package audit

import (
	"testing"
)

func TestDefaultRetentionOptions_DefaultAge(t *testing.T) {
	opts := DefaultRetentionOptions()
	if opts.DefaultMaxAgeDays != 90 {
		t.Errorf("expected 90, got %d", opts.DefaultMaxAgeDays)
	}
}

func TestDefaultRetentionOptions_NoPrefixRules(t *testing.T) {
	opts := DefaultRetentionOptions()
	if len(opts.PrefixRules) != 0 {
		t.Errorf("expected no rules, got %d", len(opts.PrefixRules))
	}
}

func TestRetentionOptions_AddRule_Valid(t *testing.T) {
	opts := DefaultRetentionOptions()
	opts.AddRule("secret/db", 30)
	if len(opts.PrefixRules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(opts.PrefixRules))
	}
	if opts.PrefixRules[0].Prefix != "secret/db" {
		t.Errorf("unexpected prefix: %s", opts.PrefixRules[0].Prefix)
	}
	if opts.PrefixRules[0].MaxAgeDays != 30 {
		t.Errorf("unexpected max age: %d", opts.PrefixRules[0].MaxAgeDays)
	}
}

func TestRetentionOptions_AddRule_EmptyPrefix_Ignored(t *testing.T) {
	opts := DefaultRetentionOptions()
	opts.AddRule("", 30)
	if len(opts.PrefixRules) != 0 {
		t.Error("empty prefix rule should be ignored")
	}
}

func TestRetentionOptions_AddRule_ZeroDays_Ignored(t *testing.T) {
	opts := DefaultRetentionOptions()
	opts.AddRule("secret/x", 0)
	if len(opts.PrefixRules) != 0 {
		t.Error("zero-day rule should be ignored")
	}
}

func TestRetentionOptions_BuildPolicy_NotNil(t *testing.T) {
	opts := DefaultRetentionOptions()
	p := opts.BuildPolicy()
	if p == nil {
		t.Fatal("expected non-nil policy")
	}
}

func TestRetentionOptions_BuildPolicy_AppliesRules(t *testing.T) {
	opts := DefaultRetentionOptions()
	opts.AddRule("secret/infra", 180)
	p := opts.BuildPolicy()
	if days, ok := p.PrefixOverrides["secret/infra"]; !ok || days != 180 {
		t.Errorf("expected override 180 for secret/infra, got %d", days)
	}
}
