package audit

import (
	"testing"
	"time"
)

func classifierSecrets() []Secret {
	now := time.Now()
	return []Secret{
		{Path: "secret/prod/db/password", Key: "password", Value: "s3cr3t", CreatedAt: now},
		{Path: "secret/prod/api/key", Key: "api_key", Value: "abc123", CreatedAt: now},
		{Path: "secret/internal/config", Key: "setting", Value: "val", CreatedAt: now},
		{Path: "public/health", Key: "status", Value: "ok", CreatedAt: now},
	}
}

func TestNewClassifier_NotNil(t *testing.T) {
	c := NewClassifier()
	if c == nil {
		t.Fatal("expected non-nil Classifier")
	}
}

func TestNewClassifier_DefaultIsInternal(t *testing.T) {
	c := NewClassifier()
	s := classifierSecrets()[2]
	if got := c.Classify(s); got != ClassificationInternal {
		t.Errorf("expected internal, got %s", got)
	}
}

func TestClassifier_SetDefault(t *testing.T) {
	c := NewClassifier()
	c.SetDefault(ClassificationPublic)
	s := classifierSecrets()[3]
	if got := c.Classify(s); got != ClassificationPublic {
		t.Errorf("expected public, got %s", got)
	}
}

func TestClassifier_AddRule_InvalidPattern(t *testing.T) {
	c := NewClassifier()
	if err := c.AddRule("[", ClassificationSecret); err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestClassifier_Classify_MatchesFirstRule(t *testing.T) {
	c := NewClassifier()
	_ = c.AddRule(`prod/db`, ClassificationSecret)
	_ = c.AddRule(`prod`, ClassificationConfidential)

	s := classifierSecrets()[0] // secret/prod/db/password
	if got := c.Classify(s); got != ClassificationSecret {
		t.Errorf("expected secret, got %s", got)
	}
}

func TestClassifier_Classify_FallsThrough(t *testing.T) {
	c := NewClassifier()
	_ = c.AddRule(`prod/db`, ClassificationSecret)

	s := classifierSecrets()[1] // secret/prod/api/key
	if got := c.Classify(s); got != ClassificationInternal {
		t.Errorf("expected internal (default), got %s", got)
	}
}

func TestClassifier_ClassifyAll_SetsTag(t *testing.T) {
	c := NewClassifier()
	_ = c.AddRule(`prod/db`, ClassificationSecret)
	_ = c.AddRule(`public`, ClassificationPublic)

	secrets := classifierSecrets()
	out := c.ClassifyAll(secrets)

	if len(out) != len(secrets) {
		t.Fatalf("expected %d secrets, got %d", len(secrets), len(out))
	}
	if out[0].Tags["classification"] != string(ClassificationSecret) {
		t.Errorf("expected secret tag on first secret, got %s", out[0].Tags["classification"])
	}
	if out[3].Tags["classification"] != string(ClassificationPublic) {
		t.Errorf("expected public tag on last secret, got %s", out[3].Tags["classification"])
	}
}

func TestClassifier_ClassifyAll_DoesNotMutateOriginal(t *testing.T) {
	c := NewClassifier()
	secrets := classifierSecrets()
	_ = c.ClassifyAll(secrets)

	for _, s := range secrets {
		if _, ok := s.Tags["classification"]; ok {
			t.Error("original secret was mutated")
		}
	}
}
