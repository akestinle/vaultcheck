package audit

import (
	"testing"
	"time"
)

var baseSecrets = []SecretMeta{
	{Path: "secret/app/db", Key: "password", UpdatedAt: time.Now().AddDate(0, 0, -5)},
	{Path: "secret/app/api", Key: "token", UpdatedAt: time.Now().AddDate(0, 0, -20)},
	{Path: "secret/infra/ssh", Key: "private_key", UpdatedAt: time.Now().AddDate(0, 0, -2)},
	{Path: "secret/infra/tls", Key: "cert", UpdatedAt: time.Now().AddDate(0, 0, -100)},
}

func TestFilter_NoOptions(t *testing.T) {
	result, err := Filter(baseSecrets, FilterOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != len(baseSecrets) {
		t.Errorf("expected %d, got %d", len(baseSecrets), len(result))
	}
}

func TestFilter_PathPrefix(t *testing.T) {
	result, err := Filter(baseSecrets, FilterOptions{PathPrefix: "secret/app"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2, got %d", len(result))
	}
}

func TestFilter_KeyPattern(t *testing.T) {
	result, err := Filter(baseSecrets, FilterOptions{KeyPattern: "^(password|token)$"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2, got %d", len(result))
	}
}

func TestFilter_MaxAgeDays(t *testing.T) {
	// only secrets updated within the last 10 days
	result, err := Filter(baseSecrets, FilterOptions{MaxAgeDays: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 (within 10 days), got %d", len(result))
	}
}

func TestFilter_ExcludePaths(t *testing.T) {
	result, err := Filter(baseSecrets, FilterOptions{ExcludePaths: []string{"secret/infra/ssh", "secret/infra/tls"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2, got %d", len(result))
	}
}

func TestFilter_InvalidKeyPattern(t *testing.T) {
	_, err := Filter(baseSecrets, FilterOptions{KeyPattern: "[invalid"})
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}
