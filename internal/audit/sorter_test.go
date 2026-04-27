package audit

import (
	"testing"
	"time"
)

func sortTestSecrets() []Secret {
	now := time.Now()
	expA := now.Add(48 * time.Hour)
	expB := now.Add(24 * time.Hour)
	return []Secret{
		{Path: "secret/zebra", Key: "password", CreatedAt: now.Add(-10 * 24 * time.Hour), ExpiresAt: &expA},
		{Path: "secret/alpha", Key: "token", CreatedAt: now.Add(-5 * 24 * time.Hour), ExpiresAt: &expB},
		{Path: "secret/mango", Key: "apikey", CreatedAt: now.Add(-20 * 24 * time.Hour)},
	}
}

func TestNewSortOptions_Defaults(t *testing.T) {
	opts := NewSortOptions("", "")
	if opts.Field != SortByPath {
		t.Errorf("expected default field %q, got %q", SortByPath, opts.Field)
	}
	if opts.Order != SortAsc {
		t.Errorf("expected default order %q, got %q", SortAsc, opts.Order)
	}
}

func TestSort_ByPath_Asc(t *testing.T) {
	secrets := sortTestSecrets()
	opts := NewSortOptions(SortByPath, SortAsc)
	result := Sort(secrets, opts)
	if result[0].Path != "secret/alpha" || result[2].Path != "secret/zebra" {
		t.Errorf("unexpected order: %v", result)
	}
}

func TestSort_ByPath_Desc(t *testing.T) {
	secrets := sortTestSecrets()
	opts := NewSortOptions(SortByPath, SortDesc)
	result := Sort(secrets, opts)
	if result[0].Path != "secret/zebra" {
		t.Errorf("expected zebra first, got %q", result[0].Path)
	}
}

func TestSort_ByAge(t *testing.T) {
	secrets := sortTestSecrets()
	opts := NewSortOptions(SortByAge, SortAsc)
	result := Sort(secrets, opts)
	// oldest first (highest age days)
	if result[0].Path != "secret/mango" {
		t.Errorf("expected mango (oldest) first, got %q", result[0].Path)
	}
}

func TestSort_ByKey(t *testing.T) {
	secrets := sortTestSecrets()
	opts := NewSortOptions(SortByKey, SortAsc)
	result := Sort(secrets, opts)
	if result[0].Key != "apikey" {
		t.Errorf("expected apikey first, got %q", result[0].Key)
	}
}

func TestSort_ByExpiry_NilLast(t *testing.T) {
	secrets := sortTestSecrets()
	opts := NewSortOptions(SortByExpiry, SortAsc)
	result := Sort(secrets, opts)
	// nil expiry should sort last
	if result[2].ExpiresAt != nil {
		t.Errorf("expected nil expiry last")
	}
}

func TestSort_DoesNotMutateInput(t *testing.T) {
	secrets := sortTestSecrets()
	origFirst := secrets[0].Path
	Sort(secrets, NewSortOptions(SortByPath, SortAsc))
	if secrets[0].Path != origFirst {
		t.Error("Sort mutated the original slice")
	}
}
