package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yourusername/vaultcheck/internal/audit"
)

var labelCmd = &cobra.Command{
	Use:   "label",
	Short: "Apply metadata labels to secrets based on path prefix rules",
	Long: `Scans secrets from Vault and applies key=value labels to secrets whose
paths match the given prefix rules. Output is written as a labeled JSON report.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vaultClientFromContext(cmd.Context())
		if err != nil {
			return err
		}

		prefixRules, _ := cmd.Flags().GetStringArray("rule")
		opts := audit.DefaultLabelOptions()
		for _, raw := range prefixRules {
			prefix, labels, parseErr := parseLabelRule(raw)
			if parseErr != nil {
				return fmt.Errorf("invalid rule %q: %w", raw, parseErr)
			}
			opts.AddRule(prefix, labels)
		}

		scanner := audit.NewScanner(client)
		secrets, err := scanner.Scan(cmd.Context(), audit.ScanOptions{})
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		labeler := opts.BuildLabeler()
		labeled := labeler.Label(secrets)

		report := audit.NewReport(labeled)
		return report.WriteJSON(os.Stdout)
	},
}

// parseLabelRule parses a rule string of the form "prefix:key=value,key=value".
func parseLabelRule(raw string) (string, map[string]string, error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", nil, fmt.Errorf("expected format prefix:key=value[,key=value]")
	}
	prefix := parts[0]
	labels := make(map[string]string)
	for _, pair := range strings.Split(parts[1], ",") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 || kv[0] == "" {
			return "", nil, fmt.Errorf("invalid key=value pair: %q", pair)
		}
		labels[kv[0]] = kv[1]
	}
	return prefix, labels, nil
}

func init() {
	labelCmd.Flags().StringArray("rule", nil, "Label rule in the form prefix:key=value[,key=value] (repeatable)")
	rootCmd.AddCommand(labelCmd)
}
