package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/yourorg/vaultcheck/internal/audit"
)

var pruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Identify and remove stale secrets based on age and path",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		client, err := vaultClientFromContext(ctx)
		if err != nil {
			return fmt.Errorf("vault client: %w", err)
		}

		maxAge, _ := cmd.Flags().GetInt("max-age-days")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		prefixes, _ := cmd.Flags().GetStringSlice("prefix")

		builder := audit.NewPruneOptionsBuilder().
			WithMaxAgeDays(maxAge).
			WithDryRun(dryRun)
		for _, p := range prefixes {
			builder = builder.WithPathPrefix(p)
		}
		opts := builder.Build()

		scanner, err := audit.NewScanner(client)
		if err != nil {
			return fmt.Errorf("scanner: %w", err)
		}

		scanOpts := audit.ScanOptions{}
		secrets, err := scanner.Scan(ctx, scanOpts)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}

		pruner := audit.NewPruner(opts)
		result := pruner.Prune(secrets)

		audit.WritePruneResult(os.Stdout, result, opts.DryRun)

		if !opts.DryRun && len(result.Pruned) > 0 {
			fmt.Fprintf(os.Stderr, "dry-run is off but deletion is not yet implemented; run with --dry-run to preview\n")
		}
		return nil
	},
}

func init() {
	pruneCmd.Flags().Int("max-age-days", 90, "Prune secrets older than this many days")
	pruneCmd.Flags().Bool("dry-run", true, "Preview pruning without deleting")
	pruneCmd.Flags().StringSlice("prefix", nil, "Restrict pruning to these path prefixes")
	rootCmd.AddCommand(pruneCmd)
}
