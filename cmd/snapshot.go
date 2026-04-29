package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"vaultcheck/internal/audit"
)

func init() {
	var snapshotDir string
	var label string
	var diffA, diffB string

	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Capture or compare point-in-time snapshots of scanned secrets",
	}

	captureCmd := &cobra.Command{
		Use:   "capture",
		Short: "Capture a new snapshot from the current scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := vaultClientFromContext(cmd.Context())
			if err != nil {
				return err
			}
			scanner, err := audit.NewScanner(client)
			if err != nil {
				return err
			}
			secrets, err := scanner.Scan(cmd.Context(), audit.ScanOptions{})
			if err != nil {
				return err
			}
			snap := audit.NewSnapshot(secrets, label)
			if err := audit.SaveSnapshot(snapshotDir, snap); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Snapshot saved: %s (id=%s, count=%d)\n", snapshotDir, snap.ID, snap.Count)
			return nil
		},
	}
	captureCmd.Flags().StringVar(&snapshotDir, "dir", "snapshots", "Directory to store snapshots")
	captureCmd.Flags().StringVar(&label, "label", "", "Optional label for the snapshot")

	diffCmd := &cobra.Command{
		Use:   "diff",
		Short: "Diff two snapshots by file path",
		RunE: func(cmd *cobra.Command, args []string) error {
			if diffA == "" || diffB == "" {
				return fmt.Errorf("both --before and --after snapshot paths are required")
			}
			before, err := audit.LoadSnapshot(filepath.Clean(diffA))
			if err != nil {
				return fmt.Errorf("loading before snapshot: %w", err)
			}
			after, err := audit.LoadSnapshot(filepath.Clean(diffB))
			if err != nil {
				return fmt.Errorf("loading after snapshot: %w", err)
			}
			result := audit.DiffSnapshots(before, after)
			audit.WriteSnapshotDiff(os.Stdout, before, after, result)
			return nil
		},
	}
	diffCmd.Flags().StringVar(&diffA, "before", "", "Path to the 'before' snapshot file")
	diffCmd.Flags().StringVar(&diffB, "after", "", "Path to the 'after' snapshot file")

	snapshotCmd.AddCommand(captureCmd, diffCmd)
	rootCmd.AddCommand(snapshotCmd)
}
