package audit

import (
	"testing"
	"time"
)

func baseSecrets() []SecretMeta {
	now := time.Now().UTC()
	return []SecretMeta{
		{Path: "secret/app/db", Key: "password", UpdatedAt: now.AddDate(0, 0, -5)},
		{Path: "secret/app/api", Key: "token", UpdatedAt: now.AddDate(0, 0, -20)},
		{Path: "secret/infra/ssh", Key: "private_key", UpdatedAt: now.AddDate(0, 0, -2)},
		{Path: "secret/infra/tls", Key: "cert", UpdatedAt: now.AddDate(0, 0, -100)},
	}
}

func TestFilter_NoOptions(t *testing.T) {
	secrets := baseSecrets()
	got, err := Filter(secrets, FilterOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(secrets) {
		t.Fatalf("expected %d, got %d", len(secrets), len(got))
	}
}

func TestFilter_PathPrefix(t *testing.T) {
	got, err := Filter(baseSecrets(), FilterOptions{PathPrefix: "secret/app"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestFilter_KeyPattern(t *testing.T) {
	got, err := Filter(baseSecrets(), FilterOptions{KeyPattern: "^(password|token)$"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestFilter_MaxAgeDays(t *testing.T) {
	// Only secrets updated within last 10 days
	got, err := Filter(baseSecrets(), FilterOptions{MaxAgeDays: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 (within 10 days), got %d", len(got))
	}
}

func TestFilter_ExcludePaths(t *testing.T) {
	got, err := Filter(baseSecrets(), FilterOptions{ExcludePaths: []string{"secret/infra"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestFilter_InvalidPattern(t *testing.T) {
	_, err := Filter(baseSecrets(), FilterOptions{KeyPattern: "[invalid"})
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}
