package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourorg/vaultcheck/internal/audit"
)

var compareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Compare two audit snapshots and report secret-level changes",
	RunE: func(cmd *cobra.Command, args []string) error {
		beforePath, _ := cmd.Flags().GetString("before")
		afterPath, _ := cmd.Flags().GetString("after")

		if beforePath == "" || afterPath == "" {
			return fmt.Errorf("--before and --after baseline files are required")
		}

		before, err := audit.LoadBaseline(beforePath)
		if err != nil {
			return fmt.Errorf("loading before baseline: %w", err)
		}

		after, err := audit.LoadBaseline(afterPath)
		if err != nil {
			return fmt.Errorf("loading after baseline: %w", err)
		}

		beforeSecrets := baselineToSlice(before)
		afterSecrets := baselineToSlice(after)

		result := audit.Compare(beforeSecrets, afterSecrets)

		fmt.Fprintf(os.Stdout, "Comparison at %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(os.Stdout, "Added: %d  Removed: %d  Changed: %d  Unchanged: %d\n\n",
			len(result.Added), len(result.Removed), len(result.Changed), len(result.Unchanged))

		if err := audit.WriteCompareResult(os.Stdout, result); err != nil {
			return fmt.Errorf("writing compare result: %w", err)
		}

		if result.HasChanges() {
			os.Exit(1)
		}
		return nil
	},
}

func baselineToSlice(b *audit.Baseline) []audit.Secret {
	result := make([]audit.Secret, 0, len(b.Secrets))
	for _, s := range b.Secrets {
		result = append(result, s)
	}
	return result
}

func init() {
	compareCmd.Flags().String("before", "", "Path to the baseline snapshot taken before changes")
	compareCmd.Flags().String("after", "", "Path to the baseline snapshot taken after changes")
	rootCmd.AddCommand(compareCmd)
}
