package audit

import (
	"testing"
	"time"
)

func TestScanOptions_EffectiveAsOf_Zero(t *testing.T) {
	var o ScanOptions
	before := time.Now()
	got := o.effectiveAsOf()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Errorf("effectiveAsOf() = %v, want between %v and %v", got, before, after)
	}
}

func TestScanOptions_EffectiveAsOf_Set(t *testing.T) {
	fixed := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
	o := ScanOptions{AsOf: fixed}
	if got := o.effectiveAsOf(); !got.Equal(fixed) {
		t.Errorf("effectiveAsOf() = %v, want %v", got, fixed)
	}
}

func TestScanOptions_ToFilterOptions_Defaults(t *testing.T) {
	o := ScanOptions{}
	fo := o.toFilterOptions()
	if fo.PathPrefix != "" {
		t.Errorf("PathPrefix = %q, want empty", fo.PathPrefix)
	}
	if fo.KeyPattern != "" {
		t.Errorf("KeyPattern = %q, want empty", fo.KeyPattern)
	}
	if fo.MaxAgeDays != 0 {
		t.Errorf("MaxAgeDays = %d, want 0", fo.MaxAgeDays)
	}
}

func TestScanOptions_ToFilterOptions_Values(t *testing.T) {
	fixed := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	o := ScanOptions{
		PathPrefix:   "secret/prod",
		KeyPattern:   "^db_",
		MaxAgeDays:   30,
		ExcludePaths: []string{"secret/prod/legacy"},
		AsOf:         fixed,
	}
	fo := o.toFilterOptions()
	if fo.PathPrefix != o.PathPrefix {
		t.Errorf("PathPrefix = %q, want %q", fo.PathPrefix, o.PathPrefix)
	}
	if fo.KeyPattern != o.KeyPattern {
		t.Errorf("KeyPattern = %q, want %q", fo.KeyPattern, o.KeyPattern)
	}
	if fo.MaxAgeDays != o.MaxAgeDays {
		t.Errorf("MaxAgeDays = %d, want %d", fo.MaxAgeDays, o.MaxAgeDays)
	}
	if len(fo.ExcludePaths) != 1 || fo.ExcludePaths[0] != "secret/prod/legacy" {
		t.Errorf("ExcludePaths = %v, want [secret/prod/legacy]", fo.ExcludePaths)
	}
	if !fo.AsOf.Equal(fixed) {
		t.Errorf("AsOf = %v, want %v", fo.AsOf, fixed)
	}
}

func TestScanOptions_ToFilterOptions_AsOf_Propagated(t *testing.T) {
	o := ScanOptions{MaxAgeDays: 7}
	before := time.Now()
	fo := o.toFilterOptions()
	after := time.Now()
	if fo.AsOf.Before(before) || fo.AsOf.After(after) {
		t.Errorf("AsOf not set to approximately now: %v", fo.AsOf)
	}
}
