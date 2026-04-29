package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func prunerSecret(path string, daysOld int) Secret {
	return Secret{
		Path:      path,
		Key:       "value",
		Value:     "secret",
		UpdatedAt: time.Now().UTC().AddDate(0, 0, -daysOld),
	}
}

func TestNewPruner_NotNil(t *testing.T) {
	p := NewPruner(PruneOptions{MaxAgeDays: 30})
	if p == nil {
		t.Fatal("expected non-nil Pruner")
	}
}

func TestPruner_Prune_Empty(t *testing.T) {
	p := NewPruner(PruneOptions{MaxAgeDays: 30})
	r := p.Prune(nil)
	if len(r.Pruned) != 0 || len(r.Retained) != 0 {
		t.Fatal("expected empty result for nil input")
	}
}

func TestPruner_Prune_OldSecretRemoved(t *testing.T) {
	p := NewPruner(PruneOptions{MaxAgeDays: 30})
	secrets := []Secret{
		prunerSecret("secret/old", 60),
		prunerSecret("secret/new", 10),
	}
	r := p.Prune(secrets)
	if len(r.Pruned) != 1 || r.Pruned[0].Path != "secret/old" {
		t.Fatalf("expected old secret pruned, got %v", r.Pruned)
	}
	if len(r.Retained) != 1 || r.Retained[0].Path != "secret/new" {
		t.Fatalf("expected new secret retained, got %v", r.Retained)
	}
}

func TestPruner_Prune_ZeroMaxAge_RetainsAll(t *testing.T) {
	p := NewPruner(PruneOptions{MaxAgeDays: 0})
	secrets := []Secret{
		prunerSecret("secret/old", 365),
	}
	r := p.Prune(secrets)
	if len(r.Pruned) != 0 {
		t.Fatal("expected no secrets pruned when MaxAgeDays is 0")
	}
	if len(r.Retained) != 1 {
		t.Fatal("expected secret retained")
	}
}

func TestPruner_Prune_PathPrefix_Filtered(t *testing.T) {
	p := NewPruner(PruneOptions{MaxAgeDays: 30, PathPrefixes: []string{"infra/"}})
	secrets := []Secret{
		prunerSecret("infra/db", 60),
		prunerSecret("app/token", 60),
	}
	r := p.Prune(secrets)
	if len(r.Pruned) != 1 || r.Pruned[0].Path != "infra/db" {
		t.Fatalf("expected only infra secret pruned, got %v", r.Pruned)
	}
}

func TestPruner_Prune_SortedOutput(t *testing.T) {
	p := NewPruner(PruneOptions{MaxAgeDays: 10})
	secrets := []Secret{
		prunerSecret("z/secret", 20),
		prunerSecret("a/secret", 20),
		prunerSecret("m/secret", 20),
	}
	r := p.Prune(secrets)
	if r.Pruned[0].Path != "a/secret" || r.Pruned[2].Path != "z/secret" {
		t.Fatalf("expected sorted pruned output, got %v", r.Pruned)
	}
}

func TestWritePruneResult_ContainsStatus(t *testing.T) {
	r := PruneResult{
		Pruned:   []Secret{prunerSecret("old/key", 60)},
		Retained: []Secret{prunerSecret("new/key", 5)},
	}
	var buf bytes.Buffer
	WritePruneResult(&buf, r, false)
	out := buf.String()
	if !strings.Contains(out, "PRUNED") {
		t.Error("expected PRUNED in output")
	}
	if !strings.Contains(out, "RETAINED") {
		t.Error("expected RETAINED in output")
	}
}
