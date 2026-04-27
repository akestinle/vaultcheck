package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vaultcheck/internal/audit"
)

var (
	anomalyMinLen    int
	anomalyMaxAgeDays int
	anomalyMount     string
)

var anomalyCmd = &cobra.Command{
	Use:   "anomaly",
	Short: "Detect anomalies in Vault secrets",
	Long:  `Scans secrets for duplicate values, short secrets, and secrets that have not been rotated recently.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vaultClientFromContext(cmd.Context())
		if err != nil {
			return fmt.Errorf("vault client: %w", err)
		}

		scanner, err := audit.NewScanner(client, anomalyMount)
		if err != nil {
			return fmt.Errorf("scanner: %w", err)
		}

		secrets, err := scanner.Scan(cmd.Context(), audit.ScanOptions{})
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}

		detector := audit.NewAnomalyDetector(anomalyMinLen, anomalyMaxAgeDays)
		anomalies := detector.Detect(secrets)

		audit.WriteAnomalies(os.Stdout, anomalies)

		if len(anomalies) > 0 {
			fmt.Fprintf(os.Stderr, "\n%d anomaly(s) detected.\n", len(anomalies))
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	anomalyCmd.Flags().IntVar(&anomalyMinLen, "min-length", 16, "Minimum acceptable secret value length")
	anomalyCmd.Flags().IntVar(&anomalyMaxAgeDays, "max-age-days", 90, "Maximum days before a secret is flagged for missing rotation")
	anomalyCmd.Flags().StringVar(&anomalyMount, "mount", "secret", "Vault KV mount path to scan")
	rootCmd.AddCommand(anomalyCmd)
}
