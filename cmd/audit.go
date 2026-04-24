package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/example/vaultcheck/internal/audit"
)

var (
	auditMount  string
	auditPath   string
	auditFormat string
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Scan a Vault KV mount and report secret metadata",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vaultClientFromContext(cmd.Context())
		if err != nil {
			return fmt.Errorf("vault client: %w", err)
		}

		scanner := audit.NewScanner(client, auditMount)
		secrets, err := scanner.Scan(cmd.Context(), auditPath)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}

		report := audit.NewReport(auditMount, secrets)

		switch auditFormat {
		case "json":
			return report.WriteJSON(os.Stdout)
		case "table":
			return report.WriteTable(os.Stdout)
		default:
			return fmt.Errorf("unknown format %q: use 'json' or 'table'", auditFormat)
		}
	},
}

func init() {
	auditCmd.Flags().StringVar(&auditMount, "mount", "secret", "KV v2 mount path")
	auditCmd.Flags().StringVar(&auditPath, "path", "", "Base path to scan (default: mount root)")
	auditCmd.Flags().StringVar(&auditFormat, "format", "table", "Output format: table or json")
	rootCmd.AddCommand(auditCmd)
}
