package audit

import (
	"testing"
	"time"
)

func baseSecrets() []SecretMeta {
	now := time.Now()
	return []SecretMeta{
		{Path: "secret/app/db", Key: "password", LastUpdated: now.AddDate(0, 0, -90)},
		{Path: "secret/app/api", Key: "token", LastUpdated: now.AddDate(0, 0, -10)},
		{Path: "secret/infra/ssh", Key: "private_key", LastUpdated: now.AddDate(0, 0, -200)},
		{Path: "secret/infra/tls", Key: "cert", LastUpdated: now.AddDate(0, 0, -5)},
	}
}

func TestFilter_NoOptions(t *testing.T) {
	secrets := baseSecrets()
	result := Filter(secrets, FilterOptions{})
	if len(result) != len(secrets) {
		t.Fatalf("expected %d secrets, got %d", len(secrets), len(result))
	}
}

func TestFilter_PathPrefix(t *testing.T) {
	result := Filter(baseSecrets(), FilterOptions{PathPrefix: "secret/app"})
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	for _, s := range result {
		if s.Path[:10] != "secret/app" {
			t.Errorf("unexpected path %s", s.Path)
		}
	}
}

func TestFilter_KeyPattern(t *testing.T) {
	result := Filter(baseSecrets(), FilterOptions{KeyPattern: "key"})
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Key != "private_key" {
		t.Errorf("unexpected key %s", result[0].Key)
	}
}

func TestFilter_MaxAgeDays(t *testing.T) {
	// Only secrets older than 30 days should pass.
	result := Filter(baseSecrets(), FilterOptions{MaxAgeDays: 30})
	if len(result) != 2 {
		t.Fatalf("expected 2 old secrets, got %d", len(result))
	}
}

func TestFilter_Combined(t *testing.T) {
	// infra prefix + older than 100 days → only ssh key
	result := Filter(baseSecrets(), FilterOptions{
		PathPrefix: "secret/infra",
		MaxAgeDays: 100,
	})
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Key != "private_key" {
		t.Errorf("unexpected key %s", result[0].Key)
	}
}

func TestFilter_EmptyInput(t *testing.T) {
	result := Filter(nil, FilterOptions{PathPrefix: "secret/"})
	if result != nil && len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}
