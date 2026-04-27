package audit

import (
	"testing"
	"time"
)

var grouperSecrets = []Secret{
	{Path: "app/db/password", Key: "password", Owner: "team-a", Tags: []string{"db", "critical"}},
	{Path: "app/api/token", Key: "token", Owner: "team-b", Tags: []string{"api"}},
	{Path: "infra/tls/cert", Key: "cert", Owner: "team-a", Tags: []string{"tls"}},
	{Path: "infra/ssh/key", Key: "key", Owner: "", Tags: nil},
	{Path: "app/cache/secret", Key: "secret", Owner: "team-b", Tags: []string{"cache", "db"}},
}

func init() {
	for i := range grouperSecrets {
		grouperSecrets[i].CreatedAt = time.Now().Add(-24 * time.Hour)
	}
}

func TestNewGrouper_NotNil(t *testing.T) {
	g := NewGrouper(GroupByPrefix)
	if g == nil {
		t.Fatal("expected non-nil Grouper")
	}
}

func TestGrouper_ByPrefix(t *testing.T) {
	g := NewGrouper(GroupByPrefix)
	groups := g.Group(grouperSecrets)

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].Key != "app" {
		t.Errorf("expected first group key 'app', got %q", groups[0].Key)
	}
	if len(groups[0].Secrets) != 3 {
		t.Errorf("expected 3 secrets in 'app', got %d", len(groups[0].Secrets))
	}
}

func TestGrouper_ByOwner(t *testing.T) {
	g := NewGrouper(GroupByOwner)
	groups := g.Group(grouperSecrets)

	keys := map[string]int{}
	for _, gr := range groups {
		keys[gr.Key] = len(gr.Secrets)
	}

	if keys["team-a"] != 2 {
		t.Errorf("expected 2 secrets for team-a, got %d", keys["team-a"])
	}
	if keys["unknown"] != 1 {
		t.Errorf("expected 1 secret for unknown owner, got %d", keys["unknown"])
	}
}

func TestGrouper_ByTag_FirstTag(t *testing.T) {
	g := NewGrouper(GroupByTag)
	groups := g.Group(grouperSecrets)

	keys := map[string]int{}
	for _, gr := range groups {
		keys[gr.Key] = len(gr.Secrets)
	}

	if keys["untagged"] != 1 {
		t.Errorf("expected 1 untagged secret, got %d", keys["untagged"])
	}
	if keys["db"] != 1 {
		t.Errorf("expected 1 secret with first tag 'db', got %d", keys["db"])
	}
}

func TestGrouper_Empty(t *testing.T) {
	g := NewGrouper(GroupByPrefix)
	groups := g.Group(nil)
	if len(groups) != 0 {
		t.Errorf("expected 0 groups for empty input, got %d", len(groups))
	}
}

func TestGrouper_SortedKeys(t *testing.T) {
	g := NewGrouper(GroupByPrefix)
	groups := g.Group(grouperSecrets)
	for i := 1; i < len(groups); i++ {
		if groups[i-1].Key > groups[i].Key {
			t.Errorf("groups not sorted: %q > %q", groups[i-1].Key, groups[i].Key)
		}
	}
}
