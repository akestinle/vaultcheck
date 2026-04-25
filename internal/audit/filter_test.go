package audit

import (
	"testing"
	"time"
)

var baseSecrets = []SecretMeta{
	{Path: "secret/app/db", Key: "password", UpdatedAt: time.Now()},
	{Path: "secret/app/api", Key: "token", UpdatedAt: time.Now().AddDate(0, 0, -10)},
	{Path: "secret/infra/ssh", Key: "private_key", UpdatedAt: time.Now().AddDate(0, 0, -40)},
	{Path: "secret/infra/tls", Key: "cert", UpdatedAt: time.Now()},
}

func TestFilter_NoOptions(t *testing.T) {
	out, err := Filter(baseSecrets, FilterOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != len(baseSecrets) {
		t.Errorf("expected %d secrets, got %d", len(baseSecrets), len(out))
	}
}

func TestFilter_PathPrefix(t *testing.T) {
	out, err := Filter(baseSecrets, FilterOptions{PathPrefix: "secret/app"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("expected 2, got %d", len(out))
	}
}

func TestFilter_KeyPattern(t *testing.T) {
	out, err := Filter(baseSecrets, FilterOptions{KeyPattern: "^(password|token)$"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("expected 2, got %d", len(out))
	}
}

func TestFilter_MaxAgeDays(t *testing.T) {
	// Only secrets updated within last 5 days should pass
	out, err := Filter(baseSecrets, FilterOptions{MaxAgeDays: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("expected 2 recent secrets, got %d", len(out))
	}
}

func TestFilter_ExcludePaths(t *testing.T) {
	out, err := Filter(baseSecrets, FilterOptions{ExcludePaths: []string{"secret/infra"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("expected 2, got %d", len(out))
	}
}

func TestFilter_InvalidPattern(t *testing.T) {
	_, err := Filter(baseSecrets, FilterOptions{KeyPattern: "[invalid"})
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}
