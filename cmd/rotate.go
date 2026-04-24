package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yourorg/vaultcheck/internal/rotation"
)

func init() {
	var (
		paths      []string
		minLength  int
		dryRun     bool
		outputFmt  string
	)

	rotateCmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate secrets stored in Vault",
		Long: `Rotate one or more secrets at the given Vault paths.

A new random value is generated for each secret and written back to Vault.
Use --dry-run to preview which paths would be rotated without making changes.`,
		Example: `  vaultcheck rotate --path secret/db/password --path secret/api/key
  vaultcheck rotate --path secret/db/password --length 32 --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(paths) == 0 {
				return fmt.Errorf("at least one --path must be specified")
			}

			if dryRun {
				cmd.Println("[dry-run] The following paths would be rotated:")
				for _, p := range paths {
					cmd.Printf("  - %s\n", p)
				}
				return nil
			}

			client, err := vaultClientFromContext(cmd.Context())
			if err != nil {
				return fmt.Errorf("vault client: %w", err)
			}

			gen, err := rotation.NewRandomGenerator(minLength)
			if err != nil {
				return fmt.Errorf("generator: %w", err)
			}

			rotator, err := rotation.NewRotator(client, gen)
			if err != nil {
				return fmt.Errorf("rotator: %w", err)
			}

			var failures []string
			for _, path := range paths {
				if err := rotator.Rotate(cmd.Context(), path); err != nil {
					fmt.Fprintf(os.Stderr, "error rotating %s: %v\n", path, err)
					failures = append(failures, path)
					continue
				}
				switch strings.ToLower(outputFmt) {
				case "json":
					cmd.Printf(`{"status":"rotated","path":%q}%s`, path, "\n")
				default:
					cmd.Printf("rotated: %s\n", path)
				}
			}

			if len(failures) > 0 {
				return fmt.Errorf("%d path(s) failed to rotate: %s",
					len(failures), strings.Join(failures, ", "))
			}
			return nil
		},
	}

	rotateCmd.Flags().StringArrayVar(&paths, "path", nil,
		"Vault secret path to rotate (repeatable)")
	rotateCmd.Flags().IntVar(&minLength, "length", 24,
		"Minimum length of the generated secret value")
	rotateCmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Print paths that would be rotated without making changes")
	rotateCmd.Flags().StringVarP(&outputFmt, "output", "o", "text",
		"Output format: text or json")

	rootCmd.AddCommand(rotateCmd)
}
