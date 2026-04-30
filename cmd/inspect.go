package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vaultcheck/internal/audit"
)

func init() {
	var secretPath string
	var withScorer bool
	var withTagger bool

	inspectCmd := &cobra.Command{
		Use:   "inspect",
		Short: "Deep-inspect a single secret and report risk, tags, labels, and issues",
		RunE: func(cmd *cobra.Command, args []string) error {
			if secretPath == "" {
				return fmt.Errorf("--path is required")
			}

			client, err := vaultClientFromContext(cmd.Context())
			if err != nil {
				return err
			}

			scanner, err := audit.NewScanner(client)
			if err != nil {
				return fmt.Errorf("scanner: %w", err)
			}

			secrets, err := scanner.Scan(cmd.Context(), audit.ScanOptions{PathPrefix: secretPath})
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			var target *audit.Secret
			for i := range secrets {
				if secrets[i].Path == secretPath {
					target = &secrets[i]
					break
				}
			}
			if target == nil {
				return fmt.Errorf("secret not found: %s", secretPath)
			}

			var scorer *audit.Scorer
			if withScorer {
				scorer = audit.NewScorer()
			}

			var tagger *audit.Tagger
			if withTagger {
				tagger = audit.NewTagger()
			}

			ins := audit.NewInspector(scorer, tagger, nil)
			result := ins.Inspect(*target)
			audit.WriteInspectResult(os.Stdout, result)
			return nil
		},
	}

	inspectCmd.Flags().StringVar(&secretPath, "path", "", "Exact path of the secret to inspect")
	inspectCmd.Flags().BoolVar(&withScorer, "score", true, "Include risk scoring")
	inspectCmd.Flags().BoolVar(&withTagger, "tag", false, "Apply tagging rules during inspection")

	rootCmd.AddCommand(inspectCmd)
}
