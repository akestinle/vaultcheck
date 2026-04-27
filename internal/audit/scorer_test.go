package audit

import (
	"testing"
	"time"
)

func TestNewScorer_Defaults(t *testing.T) {
	s := NewScorer()
	if s == nil {
		t.Fatal("expected non-nil scorer")
	}
	if s.ExpiredWeight != 40 {
		t.Errorf("expected ExpiredWeight 40, got %d", s.ExpiredWeight)
	}
	if s.ExpiringDays != 14 {
		t.Errorf("expected ExpiringDays 14, got %d", s.ExpiringDays)
	}
}

func TestScorer_Score_Expired(t *testing.T) {
	s := NewScorer()
	past := time.Now().Add(-24 * time.Hour)
	sec := Secret{Path: "secret/expired", ExpiresAt: &past}
	res := s.Score(sec)
	if res.Score < s.ExpiredWeight {
		t.Errorf("expected score >= %d for expired secret, got %d", s.ExpiredWeight, res.Score)
	}
	if res.Level != RiskCritical && res.Level != RiskHigh {
		t.Errorf("expected high/critical risk for expired secret, got %s", res.Level)
	}
}

func TestScorer_Score_NoOwner(t *testing.T) {
	s := NewScorer()
	sec := Secret{Path: "secret/noowner", Owner: ""}
	res := s.Score(sec)
	if res.Score < s.NoOwnerWeight {
		t.Errorf("expected score >= %d for no-owner secret, got %d", s.NoOwnerWeight, res.Score)
	}
}

func TestScorer_Score_LowRisk(t *testing.T) {
	s := NewScorer()
	future := time.Now().Add(90 * 24 * time.Hour)
	sec := Secret{Path: "secret/healthy", Owner: "team-a", ExpiresAt: &future, CreatedAt: time.Now()}
	res := s.Score(sec)
	if res.Level != RiskLow {
		t.Errorf("expected low risk, got %s (score %d)", res.Level, res.Score)
	}
}

func TestScorer_ScoreAll_Sorted(t *testing.T) {
	s := NewScorer()
	past := time.Now().Add(-24 * time.Hour)
	secrets := []Secret{
		{Path: "a", Owner: "x"},
		{Path: "b", ExpiresAt: &past},
		{Path: "c", Owner: ""},
	}
	results := s.ScoreAll(secrets)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for i := 1; i < len(results); i++ {
		if results[i].Score > results[i-1].Score {
			t.Errorf("results not sorted descending at index %d", i)
		}
	}
}

func TestRiskLevel_Boundaries(t *testing.T) {
	cases := []struct {
		score int
		want  RiskLevel
	}{
		{0, RiskLow},
		{14, RiskLow},
		{15, RiskMedium},
		{29, RiskMedium},
		{30, RiskHigh},
		{49, RiskHigh},
		{50, RiskCritical},
	}
	for _, tc := range cases {
		got := riskLevel(tc.score)
		if got != tc.want {
			t.Errorf("riskLevel(%d) = %s, want %s", tc.score, got, tc.want)
		}
	}
}
