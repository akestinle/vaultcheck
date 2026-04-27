package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"vaultcheck/internal/audit"
)

var baselineFile string

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Capture or compare a secret baseline snapshot",
}

var baselineCaptureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture current secrets into a baseline file",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vaultClientFromContext(cmd.Context())
		if err != nil {
			return err
		}
		scanner := audit.NewScanner(client)
		secrets, err := scanner.Scan(cmd.Context(), audit.ScanOptions{})
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		b := audit.NewBaseline(secrets)
		if err := audit.SaveBaseline(b, baselineFile); err != nil {
			return fmt.Errorf("save baseline: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Baseline saved to %s (%d secrets)\n", baselineFile, len(secrets))
		return nil
	},
}

var baselineDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Diff current secrets against a saved baseline",
	RunE: func(cmd *cobra.Command, args []string) error {
		old, err := audit.LoadBaseline(baselineFile)
		if err != nil {
			return fmt.Errorf("load baseline: %w", err)
		}
		client, err := vaultClientFromContext(cmd.Context())
		if err != nil {
			return err
		}
		scanner := audit.NewScanner(client)
		secrets, err := scanner.Scan(cmd.Context(), audit.ScanOptions{})
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		current := audit.NewBaseline(secrets)
		entries := audit.DiffBaselines(old, current)
		audit.WriteBaselineDiff(cmd.OutOrStdout(), entries)
		if len(entries) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	baselineCmd.PersistentFlags().StringVarP(&baselineFile, "file", "f", "baseline.json", "Path to baseline JSON file")
	baselineCmd.AddCommand(baselineCaptureCmd)
	baselineCmd.AddCommand(baselineDiffCmd)
	rootCmd.AddCommand(baselineCmd)
}
