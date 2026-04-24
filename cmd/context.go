package cmd

import (
	"context"

	"github.com/yourorg/vaultcheck/internal/vault"
)

type contextKey string

const vaultClientKey contextKey = "vaultClient"

// withVaultClient stores a Vault client in the given context.
func withVaultClient(ctx context.Context, client *vault.Client) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, vaultClientKey, client)
}

// vaultClientFromContext retrieves the Vault client from context.
// Returns nil if not present.
func vaultClientFromContext(ctx context.Context) *vault.Client {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(vaultClientKey).(*vault.Client)
	return v
}
