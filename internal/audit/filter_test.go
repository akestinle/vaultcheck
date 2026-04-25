package audit

import (
	"testing"
	"time"
)

func baseSecrets() []SecretMeta {
	now := time.Now()
	return []SecretMeta{
		{Path: "secret/app/db", Key: "password", UpdatedAt: now},
		{Path: "secret/app/api", Key: "token", UpdatedAt: now.AddDate(0, 0, -10)},
		{Path: "secret/infra/tls", Key: "cert", UpdatedAt: now.AddDate(0, 0, -40)},
		{Path: "secret/infra/ssh", Key: "private_key", UpdatedAt: now},
	}
}

func TestFilter_NoOptions(t *testing.T) {
	secrets := baseSecrets()
	got := Filter(secrets, FilterOptions{})
	if len(got) != len(secrets) {
		t.Fatalf("expected %d secrets, got %d", len(secrets), len(got))
	}
}

func TestFilter_PathPrefix(t *testing.T) {
	got := Filter(baseSecrets(), FilterOptions{PathPrefix: "secret/app/"})
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestFilter_KeyPattern(t *testing.T) {
	got := Filter(baseSecrets(), FilterOptions{KeyPattern: "^(password|token)$"})
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestFilter_MaxAgeDays(t *testing.T) {
	// Only secrets updated within last 5 days should survive.
	got := Filter(baseSecrets(), FilterOptions{MaxAgeDays: 5})
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestFilter_ExcludePaths(t *testing.T) {
	got := Filter(baseSecrets(), FilterOptions{ExcludePaths: []string{"secret/infra/tls", "secret/infra/ssh"}})
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestFilter_Combined(t *testing.T) {
	got := Filter(baseSecrets(), FilterOptions{
		PathPrefix:   "secret/app/",
		MaxAgeDays:   5,
		ExcludePaths: []string{"secret/app/api"},
	})
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].Key != "password" {
		t.Fatalf("unexpected key %q", got[0].Key)
	}
}
