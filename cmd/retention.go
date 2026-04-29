package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vaultcheck/internal/audit"
)

func init() {
	var (
		mount      string
		prefix     string
		maxAge     int
		overrides  []string
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:   "retention",
		Short: "Evaluate secrets against retention policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := vaultClientFromContext(cmd.Context())
			if err != nil {
				return fmt.Errorf("vault client: %w", err)
			}

			scanner, err := audit.NewScanner(client, mount)
			if err != nil {
				return fmt.Errorf("scanner: %w", err)
			}

			secrets, err := scanner.Scan(cmd.Context(), audit.ScanOptions{PathPrefix: prefix})
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			policy := audit.NewRetentionPolicy(maxAge)
			for _, ov := range overrides {
				parts := strings.SplitN(ov, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid override %q: expected prefix=days", ov)
				}
				days, err := strconv.Atoi(parts[1])
				if err != nil {
					return fmt.Errorf("invalid days in override %q: %w", ov, err)
				}
				policy.AddPrefixOverride(parts[0], days)
			}

			results := policy.Evaluate(secrets)

			if outputJSON {
				enc := newJSONEncoder(os.Stdout)
				return enc.Encode(results)
			}

			audit.WriteRetentionReport(os.Stdout, results)
			return nil
		},
	}

	cmd.Flags().StringVar(&mount, "mount", "secret", "Vault KV mount path")
	cmd.Flags().StringVar(&prefix, "prefix", "", "Filter secrets by path prefix")
	cmd.Flags().IntVar(&maxAge, "max-age", 90, "Default maximum secret age in days")
	cmd.Flags().StringArrayVar(&overrides, "override", nil, "Prefix-specific max age overrides (format: prefix=days)")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output results as JSON")

	rootCmd.AddCommand(cmd)
}
