package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/vaultcheck/internal/audit"
)

func init() {
	var (
		warnDays     int
		criticalDays int
		minLevel     string
		pathPrefix   string
	)

	cmd := &cobra.Command{
		Use:   "stale",
		Short: "Classify secrets by rotation age",
		Long:  "Scan Vault secrets and report which ones are stale based on their age.",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := vaultClientFromContext(cmd.Context())
			if err != nil {
				return err
			}

			scanner, err := audit.NewScanner(client)
			if err != nil {
				return fmt.Errorf("scanner: %w", err)
			}

			secrets, err := scanner.Scan(cmd.Context(), audit.ScanOptions{
				PathPrefix: pathPrefix,
			})
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			staler := audit.NewStaler(audit.StalenessOptions{
				WarnAfterDays:     warnDays,
				CriticalAfterDays: criticalDays,
			})

			results := staler.ClassifyAll(secrets)

			min := audit.StalenessLevel(minLevel)
			results = audit.Filter(results, min)

			if len(results) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No stale secrets found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PATH\tAGE (days)\tLEVEL")
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%d\t%s\n", r.Secret.Path, r.AgeDays, r.Level)
			}
			return w.Flush()
		},
	}

	cmd.Flags().IntVar(&warnDays, "warn-after", 90, "Days before a secret is considered stale (warn)")
	cmd.Flags().IntVar(&criticalDays, "critical-after", 180, "Days before a secret is considered critically stale")
	cmd.Flags().StringVar(&minLevel, "min-level", "warn", "Minimum staleness level to display (ok|warn|critical)")
	cmd.Flags().StringVar(&pathPrefix, "prefix", "", "Vault path prefix to scan")

	rootCmd.AddCommand(cmd)
}
