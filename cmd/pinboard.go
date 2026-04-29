package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"vaultcheck/internal/audit"
)

// global in-process pinboard for the session
var sessionPinboard = audit.NewPinboard()

var pinboardCmd = &cobra.Command{
	Use:   "pinboard",
	Short: "Manage the session pinboard of flagged secret paths",
}

var pinboardAddCmd = &cobra.Command{
	Use:   "add <path> [annotation]",
	Short: "Pin a secret path with an optional annotation",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		annotation := ""
		if len(args) == 2 {
			annotation = args[1]
		}
		if err := sessionPinboard.Add(path, annotation); err != nil {
			return fmt.Errorf("pinboard add: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "pinned: %s\n", path)
		return nil
	},
}

var pinboardRemoveCmd = &cobra.Command{
	Use:   "remove <path>",
	Short: "Remove a pinned secret path",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !sessionPinboard.Remove(args[0]) {
			return fmt.Errorf("pinboard remove: path not found: %s", args[0])
		}
		fmt.Fprintf(cmd.OutOrStdout(), "unpinned: %s\n", args[0])
		return nil
	},
}

var pinboardListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all pinned secret paths",
	RunE: func(cmd *cobra.Command, _ []string) error {
		audit.WritePinboard(cmd.OutOrStdout(), sessionPinboard)
		return nil
	},
}

func init() {
	pinboardCmd.AddCommand(pinboardAddCmd)
	pinboardCmd.AddCommand(pinboardRemoveCmd)
	pinboardCmd.AddCommand(pinboardListCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	rootCmd.AddCommand(pinboardCmd)
}
