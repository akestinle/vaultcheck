package audit

import (
	"testing"
	"time"
)

func dupSecrets() []Secret {
	now := time.Now()
	return []Secret{
		{Path: "secret/db", Key: "password", Value: "abc", CreatedAt: now},
		{Path: "secret/db", Key: "password", Value: "xyz", CreatedAt: now}, // duplicate
		{Path: "secret/db", Key: "user", Value: "admin", CreatedAt: now},
		{Path: "secret/api", Key: "token", Value: "tok1", CreatedAt: now},
		{Path: "secret/api", Key: "token", Value: "tok2", CreatedAt: now}, // duplicate
	}
}

func TestNewDeduplicator_NotNil(t *testing.T) {
	d := NewDeduplicator()
	if d == nil {
		t.Fatal("expected non-nil Deduplicator")
	}
}

func TestDeduplicate_RemovesDuplicates(t *testing.T) {
	d := NewDeduplicator()
	result := d.Deduplicate(dupSecrets())
	if len(result) != 3 {
		t.Fatalf("expected 3 unique secrets, got %d", len(result))
	}
}

func TestDeduplicate_KeepsFirstOccurrence(t *testing.T) {
	d := NewDeduplicator()
	result := d.Deduplicate(dupSecrets())
	for _, s := range result {
		if s.Path == "secret/db" && s.Key == "password" && s.Value != "abc" {
			t.Errorf("expected first occurrence value 'abc', got %q", s.Value)
		}
	}
}

func TestDeduplicate_SortedOutput(t *testing.T) {
	d := NewDeduplicator()
	result := d.Deduplicate(dupSecrets())
	for i := 1; i < len(result); i++ {
		prev, cur := result[i-1], result[i]
		if prev.Path > cur.Path || (prev.Path == cur.Path && prev.Key > cur.Key) {
			t.Errorf("output not sorted at index %d: %s/%s before %s/%s",
				i, prev.Path, prev.Key, cur.Path, cur.Key)
		}
	}
}

func TestDeduplicate_EmptyInput(t *testing.T) {
	d := NewDeduplicator()
	result := d.Deduplicate([]Secret{})
	if len(result) != 0 {
		t.Fatalf("expected empty result, got %d items", len(result))
	}
}

func TestDeduplicator_Reset(t *testing.T) {
	d := NewDeduplicator()
	first := d.Deduplicate(dupSecrets())
	d.Reset()
	second := d.Deduplicate(dupSecrets())
	if len(first) != len(second) {
		t.Fatalf("after reset expected same count: got %d and %d", len(first), len(second))
	}
}

func TestDeduplicate_NoDuplicates(t *testing.T) {
	now := time.Now()
	secrets := []Secret{
		{Path: "a", Key: "k1", CreatedAt: now},
		{Path: "b", Key: "k2", CreatedAt: now},
		{Path: "c", Key: "k3", CreatedAt: now},
	}
	d := NewDeduplicator()
	result := d.Deduplicate(secrets)
	if len(result) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(result))
	}
}
