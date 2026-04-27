package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vaultcheck/internal/audit"
)

func init() {
	var mount string
	var by string

	groupCmd := &cobra.Command{
		Use:   "group",
		Short: "Group secrets by prefix, owner, or tag",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := vaultClientFromContext(cmd.Context())
			if err != nil {
				return fmt.Errorf("vault client: %w", err)
			}

			scanner, err := audit.NewScanner(client, mount)
			if err != nil {
				return fmt.Errorf("scanner: %w", err)
			}

			secrets, err := scanner.Scan(cmd.Context(), audit.ScanOptions{})
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			groupBy := audit.GroupBy(by)
			switch groupBy {
			case audit.GroupByPrefix, audit.GroupByOwner, audit.GroupByTag:
			default:
				return fmt.Errorf("invalid --by value %q (use prefix|owner|tag)", by)
			}

			grouper := audit.NewGrouper(groupBy)
			groups := grouper.Group(secrets)

			w := os.Stdout
			for _, g := range groups {
				fmt.Fprintf(w, "[%s] (%d secrets)\n", g.Key, len(g.Secrets))
				for _, s := range g.Secrets {
					fmt.Fprintf(w, "  %s\n", s.Path)
				}
			}

			fmt.Fprintf(w, "\nTotal groups: %d\n", len(groups))
			return nil
		},
	}

	groupCmd.Flags().StringVar(&mount, "mount", "secret", "Vault KV mount path")
	groupCmd.Flags().StringVar(&by, "by", "prefix", "Group by field: prefix, owner, tag")

	rootCmd.AddCommand(groupCmd)
}
