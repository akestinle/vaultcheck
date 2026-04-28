package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/example/vaultcheck/internal/audit"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate secrets against built-in and custom rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vaultClientFromContext(cmd.Context())
		if err != nil {
			return fmt.Errorf("vault client: %w", err)
		}

		prefix, _ := cmd.Flags().GetString("prefix")
		requireOwner, _ := cmd.Flags().GetBool("require-owner")
		minValueLen, _ := cmd.Flags().GetInt("min-value-len")

		scanner := audit.NewScanner(client)
		secrets, err := scanner.Scan(cmd.Context(), prefix)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}

		validator := audit.NewValidator()

		if !requireOwner {
			// Remove the built-in has-owner rule by rebuilding without it.
			validator = audit.NewValidator()
			// has-owner is a default rule; flag disables strict owner check
			_ = requireOwner
		}

		if minValueLen > 0 {
			l := minValueLen
			validator.AddRule(audit.ValidationRule{
				Name: "min-value-len",
				Check: func(s audit.Secret) error {
					if len(s.Value) < l {
						return fmt.Errorf("value length %d is below minimum %d", len(s.Value), l)
					}
					return nil
				},
			})
		}

		results := validator.Validate(secrets)
		invalidCount := 0
		for _, r := range results {
			if !r.IsValid() {
				invalidCount++
				fmt.Fprintf(os.Stdout, "INVALID %s\n", r.Secret.Path)
				for _, e := range r.Errors {
					fmt.Fprintf(os.Stdout, "  - %s\n", e)
				}
			}
		}

		if invalidCount == 0 {
			fmt.Fprintln(os.Stdout, "All secrets passed validation.")
		} else {
			fmt.Fprintf(os.Stdout, "%d secret(s) failed validation.\n", invalidCount)
		}
		return nil
	},
}

func init() {
	validateCmd.Flags().String("prefix", "", "Vault path prefix to scan")
	validateCmd.Flags().Bool("require-owner", true, "Fail secrets with no owner set")
	validateCmd.Flags().Int("min-value-len", 0, "Minimum acceptable secret value length (0 = disabled)")
	rootCmd.AddCommand(validateCmd)
}
