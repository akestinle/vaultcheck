package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/yourorg/vaultcheck/internal/vault"
)

var (
	vaultAddr  string
	vaultToken string
	tlsSkip    bool
)

// rootCmd is the base command for vaultcheck.
var rootCmd = &cobra.Command{
	Use:   "vaultcheck",
	Short: "Audit and rotate secrets stored in HashiCorp Vault",
	Long: `vaultcheck is a CLI tool for auditing secret freshness,
diffing Vault policies, and rotating secrets with full reporting.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Validate connectivity before any sub-command runs.
		if cmd.Name() == "help" || cmd.Name() == "version" {
			return nil
		}
		client, err := vault.NewClient(vault.Config{
			Address: vaultAddr,
			Token:   vaultToken,
			TLSSkip: tlsSkip,
		})
		if err != nil {
			return fmt.Errorf("vault client init: %w", err)
		}
		// Store client in context for sub-commands via cobra annotations.
		cmd.SetContext(withVaultClient(cmd.Context(), client))
		return nil
	},
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&vaultAddr, "address", "", "Vault server address (overrides VAULT_ADDR)")
	rootCmd.PersistentFlags().StringVar(&vaultToken, "token", "", "Vault token (overrides VAULT_TOKEN)")
	rootCmd.PersistentFlags().BoolVar(&tlsSkip, "tls-skip-verify", false, "Skip TLS certificate verification")
}
