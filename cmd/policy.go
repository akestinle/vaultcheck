package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vaultcheck/internal/policy"
)

func init() {
	var fromDir string
	var fromFile string
	var vaultPolicyName string

	policyDiffCmd := &cobra.Command{
		Use:   "policy-diff",
		Short: "Diff local policy file(s) against the policy stored in Vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := vaultClientFromContext(cmd.Context())
			if err != nil {
				return fmt.Errorf("vault client: %w", err)
			}

			var locals []*policy.Policy

			switch {
			case fromDir != "":
				locals, err = policy.LoadDir(fromDir)
				if err != nil {
					return err
				}
			case fromFile != "":
				p, loadErr := policy.LoadFromFile(fromFile)
				if loadErr != nil {
					return loadErr
				}
				locals = []*policy.Policy{p}
			default:
				return fmt.Errorf("provide --file or --dir")
			}

			for _, local := range locals {
				name := vaultPolicyName
				if name == "" {
					name = local.Name
				}

				vaultPolicy, err := client.Sys().GetPolicy(name)
				if err != nil {
					return fmt.Errorf("fetch policy %q: %w", name, err)
				}

				diffs := policy.Diff(vaultPolicy, local.Rules)
				if len(diffs) == 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "policy %q: no changes\n", name)
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "policy %q:\n", name)
				if err := policy.WriteDiff(cmd.OutOrStdout(), diffs); err != nil {
					return err
				}
			}
			return nil
		},
	}

	policyDiffCmd.Flags().StringVar(&fromFile, "file", "", "path to a single policy file (.json or .hcl)")
	policyDiffCmd.Flags().StringVar(&fromDir, "dir", "", "directory containing policy files")
	policyDiffCmd.Flags().StringVar(&vaultPolicyName, "vault-name", "", "override Vault policy name (single file mode only)")

	rootCmd.AddCommand(policyDiffCmd)

	_ = os.Stderr // suppress unused import lint in some environments
}
