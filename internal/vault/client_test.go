package vault_test

import (
	"testing"

	"github.com/yourorg/vaultcheck/internal/vault"
)

func TestNewClient_MissingAddress(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "test-token")

	_, err := vault.NewClient(vault.Config{})
	if err == nil {
		t.Fatal("expected error when VAULT_ADDR is missing, got nil")
	}
}

func TestNewClient_MissingToken(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	t.Setenv("VAULT_TOKEN", "")

	_, err := vault.NewClient(vault.Config{})
	if err == nil {
		t.Fatal("expected error when VAULT_TOKEN is missing, got nil")
	}
}

func TestNewClient_EnvFallback(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	t.Setenv("VAULT_TOKEN", "root")

	// Should succeed client construction (no network call yet).
	client, err := vault.NewClient(vault.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewClient_ExplicitConfig(t *testing.T) {
	cfg := vault.Config{
		Address: "http://127.0.0.1:8200",
		Token:   "explicit-token",
		TLSSkip: false,
	}
	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewClient_TLSSkip(t *testing.T) {
	cfg := vault.Config{
		Address: "https://127.0.0.1:8200",
		Token:   "root",
		TLSSkip: true,
	}
	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error with TLSSkip=true: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}
