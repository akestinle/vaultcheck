package audit

import (
	"testing"
	"time"
)

var stalerNow = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

func makeStaleSecret(path string, daysOld int) Secret {
	return Secret{
		Path:      path,
		Key:       "value",
		Value:     "x",
		CreatedAt: stalerNow.AddDate(0, 0, -daysOld),
	}
}

func defaultStaler() *Staler {
	return NewStaler(StalenessOptions{AsOf: stalerNow})
}

func TestNewStaler_Defaults(t *testing.T) {
	s := NewStaler(StalenessOptions{})
	if s.opts.WarnAfterDays != 90 {
		t.Errorf("expected WarnAfterDays=90, got %d", s.opts.WarnAfterDays)
	}
	if s.opts.CriticalAfterDays != 180 {
		t.Errorf("expected CriticalAfterDays=180, got %d", s.opts.CriticalAfterDays)
	}
}

func TestClassify_OK(t *testing.T) {
	s := defaultStaler()
	r := s.Classify(makeStaleSecret("sec/a", 30))
	if r.Level != StalenessOK {
		t.Errorf("expected ok, got %s", r.Level)
	}
	if r.AgeDays != 30 {
		t.Errorf("expected age 30, got %d", r.AgeDays)
	}
}

func TestClassify_Warn(t *testing.T) {
	s := defaultStaler()
	r := s.Classify(makeStaleSecret("sec/b", 100))
	if r.Level != StalenessWarn {
		t.Errorf("expected warn, got %s", r.Level)
	}
}

func TestClassify_Critical(t *testing.T) {
	s := defaultStaler()
	r := s.Classify(makeStaleSecret("sec/c", 200))
	if r.Level != StalenessCritical {
		t.Errorf("expected critical, got %s", r.Level)
	}
}

func TestClassifyAll_Count(t *testing.T) {
	s := defaultStaler()
	secrets := []Secret{
		makeStaleSecret("a", 10),
		makeStaleSecret("b", 95),
		makeStaleSecret("c", 185),
	}
	results := s.ClassifyAll(secrets)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	levels := []StalenessLevel{StalenessOK, StalenessWarn, StalenessCritical}
	for i, r := range results {
		if r.Level != levels[i] {
			t.Errorf("result[%d]: expected %s, got %s", i, levels[i], r.Level)
		}
	}
}

func TestFilter_WarnAndAbove(t *testing.T) {
	s := defaultStaler()
	secrets := []Secret{
		makeStaleSecret("a", 10),
		makeStaleSecret("b", 95),
		makeStaleSecret("c", 185),
	}
	all := s.ClassifyAll(secrets)
	filtered := Filter(all, StalenessWarn)
	if len(filtered) != 2 {
		t.Errorf("expected 2 filtered results, got %d", len(filtered))
	}
}

func TestFilter_CriticalOnly(t *testing.T) {
	s := defaultStaler()
	secrets := []Secret{
		makeStaleSecret("a", 10),
		makeStaleSecret("b", 95),
		makeStaleSecret("c", 185),
	}
	all := s.ClassifyAll(secrets)
	filtered := Filter(all, StalenessCritical)
	if len(filtered) != 1 {
		t.Errorf("expected 1 critical result, got %d", len(filtered))
	}
}
