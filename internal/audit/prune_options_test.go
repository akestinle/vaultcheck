package audit

import (
	"testing"
)

func TestDefaultPruneOptions_MaxAge(t *testing.T) {
	opts := DefaultPruneOptions()
	if opts.MaxAgeDays != 90 {
		t.Fatalf("expected default MaxAgeDays 90, got %d", opts.MaxAgeDays)
	}
}

func TestDefaultPruneOptions_DryRunFalse(t *testing.T) {
	opts := DefaultPruneOptions()
	if opts.DryRun {
		t.Fatal("expected DryRun to be false by default")
	}
}

func TestDefaultPruneOptions_NoPrefixes(t *testing.T) {
	opts := DefaultPruneOptions()
	if len(opts.PathPrefixes) != 0 {
		t.Fatal("expected no path prefixes by default")
	}
}

func TestPruneOptionsBuilder_WithMaxAgeDays(t *testing.T) {
	opts := NewPruneOptionsBuilder().WithMaxAgeDays(45).Build()
	if opts.MaxAgeDays != 45 {
		t.Fatalf("expected MaxAgeDays 45, got %d", opts.MaxAgeDays)
	}
}

func TestPruneOptionsBuilder_WithMaxAgeDays_ZeroIgnored(t *testing.T) {
	opts := NewPruneOptionsBuilder().WithMaxAgeDays(0).Build()
	if opts.MaxAgeDays != 90 {
		t.Fatalf("expected default 90 when zero passed, got %d", opts.MaxAgeDays)
	}
}

func TestPruneOptionsBuilder_WithDryRun(t *testing.T) {
	opts := NewPruneOptionsBuilder().WithDryRun(true).Build()
	if !opts.DryRun {
		t.Fatal("expected DryRun true")
	}
}

func TestPruneOptionsBuilder_WithPathPrefix(t *testing.T) {
	opts := NewPruneOptionsBuilder().
		WithPathPrefix("infra/").
		WithPathPrefix("app/").
		Build()
	if len(opts.PathPrefixes) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(opts.PathPrefixes))
	}
}

func TestPruneOptionsBuilder_WithPathPrefix_EmptyIgnored(t *testing.T) {
	opts := NewPruneOptionsBuilder().WithPathPrefix("").Build()
	if len(opts.PathPrefixes) != 0 {
		t.Fatal("expected empty prefix to be ignored")
	}
}
