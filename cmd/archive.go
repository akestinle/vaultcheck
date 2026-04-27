package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"vaultcheck/internal/audit"
)

func init() {
	var (
		mountPath  string
		archiveDir string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "archive",
		Short: "Snapshot current secrets to a local archive directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := vaultClientFromContext(cmd.Context())
			if err != nil {
				return fmt.Errorf("archive: %w", err)
			}

			scanner, err := audit.NewScanner(client, mountPath)
			if err != nil {
				return fmt.Errorf("archive: %w", err)
			}

			secrets, err := scanner.Scan(cmd.Context(), audit.ScanOptions{})
			if err != nil {
				return fmt.Errorf("archive: scan failed: %w", err)
			}

			archiver, err := audit.NewArchiver(archiveDir)
			if err != nil {
				return fmt.Errorf("archive: %w", err)
			}

			path, err := archiver.Archive(secrets)
			if err != nil {
				return fmt.Errorf("archive: %w", err)
			}

			fmt.Fprintf(os.Stdout, "Archived %d secrets to %s\n", len(secrets), path)

			if outputPath != "" {
				entry, err := audit.LoadArchive(path)
				if err != nil {
					return fmt.Errorf("archive: reload failed: %w", err)
				}
				report := audit.NewReport(entry.Secrets)
				f, err := os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("archive: output file: %w", err)
				}
				defer f.Close()
				return report.WriteJSON(f)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&mountPath, "mount", "secret", "Vault KV mount path")
	cmd.Flags().StringVar(&archiveDir, "dir", "./archives", "Directory to store archive snapshots")
	cmd.Flags().StringVar(&outputPath, "output", "", "Optional path to write JSON report of archived secrets")

	rootCmd.AddCommand(cmd)
}
