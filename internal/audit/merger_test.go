package audit

import (
	"testing"
	"time"
)

func mergerSecrets() ([]Secret, []Secret) {
	now := time.Now()
	left := []Secret{
		{Path: "secret/a", Key: "password", Value: "left-a", CreatedAt: now},
		{Path: "secret/b", Key: "token", Value: "left-b", CreatedAt: now},
	}
	right := []Secret{
		{Path: "secret/b", Key: "token", Value: "right-b", CreatedAt: now},
		{Path: "secret/c", Key: "api_key", Value: "right-c", CreatedAt: now},
	}
	return left, right
}

func TestNewMerger_NotNil(t *testing.T) {
	m := NewMerger(DefaultMergeOptions())
	if m == nil {
		t.Fatal("expected non-nil Merger")
	}
}

func TestMerge_PreferRight_Default(t *testing.T) {
	left, right := mergerSecrets()
	m := NewMerger(DefaultMergeOptions())
	result := m.Merge(left, right)

	if len(result) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(result))
	}
	// secret/b should come from right
	for _, s := range result {
		if s.Path == "secret/b" && s.Value != "right-b" {
			t.Errorf("expected right-b, got %s", s.Value)
		}
	}
}

func TestMerge_PreferLeft(t *testing.T) {
	left, right := mergerSecrets()
	m := NewMerger(MergeOptions{PreferLeft: true})
	result := m.Merge(left, right)

	if len(result) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(result))
	}
	for _, s := range result {
		if s.Path == "secret/b" && s.Value != "left-b" {
			t.Errorf("expected left-b, got %s", s.Value)
		}
	}
}

func TestMerge_SortedOutput(t *testing.T) {
	left, right := mergerSecrets()
	m := NewMerger(DefaultMergeOptions())
	result := m.Merge(left, right)

	for i := 1; i < len(result); i++ {
		if result[i].Path < result[i-1].Path {
			t.Errorf("output not sorted at index %d: %s > %s", i, result[i-1].Path, result[i].Path)
		}
	}
}

func TestMerge_EmptyLeft(t *testing.T) {
	_, right := mergerSecrets()
	m := NewMerger(DefaultMergeOptions())
	result := m.Merge(nil, right)
	if len(result) != len(right) {
		t.Errorf("expected %d secrets, got %d", len(right), len(result))
	}
}

func TestMerge_EmptyRight(t *testing.T) {
	left, _ := mergerSecrets()
	m := NewMerger(DefaultMergeOptions())
	result := m.Merge(left, nil)
	if len(result) != len(left) {
		t.Errorf("expected %d secrets, got %d", len(left), len(result))
	}
}
