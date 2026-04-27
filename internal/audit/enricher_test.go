package audit

import (
	"testing"
	"time"
)

func TestNewEnricher_NotNil(t *testing.T) {
	e := NewEnricher()
	if e == nil {
		t.Fatal("expected non-nil enricher")
	}
}

func TestEnricher_Enrich_SetsOwnerFromSource(t *testing.T) {
	e := NewEnricher()
	src := NewStaticEnrichmentSource(map[string]string{
		"secret/db/password": "team-db",
	})
	e.AddSource(src)

	secrets := []Secret{
		{Path: "secret/db/password", CreatedAt: time.Now()},
	}
	enriched := e.Enrich(secrets)
	if len(enriched) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(enriched))
	}
	if enriched[0].Owner != "team-db" {
		t.Errorf("expected owner 'team-db', got '%s'", enriched[0].Owner)
	}
}

func TestEnricher_Enrich_InfersOwnerFromPath(t *testing.T) {
	e := NewEnricher()
	secrets := []Secret{
		{Path: "secret/payments/api-key", CreatedAt: time.Now()},
	}
	enriched := e.Enrich(secrets)
	if enriched[0].Owner == "" {
		t.Error("expected inferred owner from path segment, got empty string")
	}
}

func TestEnricher_Enrich_PreservesExistingOwner(t *testing.T) {
	e := NewEnricher()
	src := NewStaticEnrichmentSource(map[string]string{
		"secret/svc/token": "team-new",
	})
	e.AddSource(src)

	secrets := []Secret{
		{Path: "secret/svc/token", Owner: "team-original", CreatedAt: time.Now()},
	}
	enriched := e.Enrich(secrets)
	if enriched[0].Owner != "team-original" {
		t.Errorf("expected original owner preserved, got '%s'", enriched[0].Owner)
	}
}

func TestStaticEnrichmentSource_Lookup(t *testing.T) {
	src := NewStaticEnrichmentSource(map[string]string{
		"secret/key": "owner-a",
	})
	owner, ok := src.Lookup("secret/key")
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if owner != "owner-a" {
		t.Errorf("expected 'owner-a', got '%s'", owner)
	}
	_, ok = src.Lookup("secret/missing")
	if ok {
		t.Error("expected lookup to fail for missing key")
	}
}
