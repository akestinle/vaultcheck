package audit

import "sort"

// RiskLevel represents the severity of a secret's risk score.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// ScoreResult holds the computed risk score and level for a secret.
type ScoreResult struct {
	Secret Secret
	Score  int
	Level  RiskLevel
}

// Scorer computes risk scores for secrets based on configurable weights.
type Scorer struct {
	ExpiredWeight    int
	ExpiringWeight   int
	OldAgeWeight     int
	NoOwnerWeight    int
	ExpiringDays     int
	OldAgeDays       int
}

// NewScorer returns a Scorer with sensible defaults.
func NewScorer() *Scorer {
	return &Scorer{
		ExpiredWeight:  40,
		ExpiringWeight: 20,
		OldAgeWeight:   15,
		NoOwnerWeight:  10,
		ExpiringDays:   14,
		OldAgeDays:     180,
	}
}

// Score computes a ScoreResult for a single secret.
func (s *Scorer) Score(sec Secret) ScoreResult {
	score := 0
	if sec.IsExpired() {
		score += s.ExpiredWeight
	} else if sec.ExpiresAt != nil && sec.AgeDays() >= float64(s.ExpiringDays) {
		score += s.ExpiringWeight
	}
	if sec.AgeDays() >= float64(s.OldAgeDays) {
		score += s.OldAgeWeight
	}
	if sec.Owner == "" {
		score += s.NoOwnerWeight
	}
	return ScoreResult{Secret: sec, Score: score, Level: riskLevel(score)}
}

// ScoreAll scores a slice of secrets and returns sorted results (highest first).
func (s *Scorer) ScoreAll(secrets []Secret) []ScoreResult {
	results := make([]ScoreResult, len(secrets))
	for i, sec := range secrets {
		results[i] = s.Score(sec)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})
	return results
}

func riskLevel(score int) RiskLevel {
	switch {
	case score >= 50:
		return RiskCritical
	case score >= 30:
		return RiskHigh
	case score >= 15:
		return RiskMedium
	default:
		return RiskLow
	}
}
