package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"vaultcheck/internal/audit"
)

var scoreCmd = &cobra.Command{
	Use:   "score",
	Short: "Score secrets by risk level",
	Long:  "Scan secrets and rank them by computed risk score based on expiry, age, and ownership.",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vaultClientFromContext(cmd.Context())
		if err != nil {
			return fmt.Errorf("vault client: %w", err)
		}

		path, _ := cmd.Flags().GetString("path")
		minLevel, _ := cmd.Flags().GetString("min-level")

		scanner, err := audit.NewScanner(client)
		if err != nil {
			return fmt.Errorf("scanner: %w", err)
		}

		secrets, err := scanner.Scan(cmd.Context(), path)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}

		scorer := audit.NewScorer()
		results := scorer.ScoreAll(secrets)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PATH\tSCORE\tLEVEL")
		fmt.Fprintln(w, "----\t-----\t-----")

		printed := 0
		for _, r := range results {
			if minLevel != "" && !meetsMinLevel(r.Level, audit.RiskLevel(minLevel)) {
				continue
			}
			fmt.Fprintf(w, "%s\t%d\t%s\n", r.Secret.Path, r.Score, r.Level)
			printed++
		}
		w.Flush()

		if printed == 0 {
			fmt.Println("No secrets matched the specified risk level.")
		}
		return nil
	},
}

func meetsMinLevel(level, min audit.RiskLevel) bool {
	order := map[audit.RiskLevel]int{
		audit.RiskLow:      0,
		audit.RiskMedium:   1,
		audit.RiskHigh:     2,
		audit.RiskCritical: 3,
	}
	return order[level] >= order[min]
}

func init() {
	scoreCmd.Flags().String("path", "secret/", "Vault path prefix to scan")
	scoreCmd.Flags().String("min-level", "", "Minimum risk level to display (low|medium|high|critical)")
	rootCmd.AddCommand(scoreCmd)
}
