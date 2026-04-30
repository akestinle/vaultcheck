package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"vaultcheck/internal/audit"
)

var pinsetStore = audit.NewPinset()

var pinsetCmd = &cobra.Command{
	Use:   "pinset",
	Short: "Manage named groups of pinned secret paths",
}

var pinsetAddCmd = &cobra.Command{
	Use:   "add <name> <path> [path...]",
	Short: "Add or replace a named pinset",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		paths := args[1:]
		if err := pinsetStore.Add(name, paths); err != nil {
			return fmt.Errorf("pinset add: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "pinset %q updated with %d path(s)\n", name, len(paths))
		return nil
	},
}

var pinsetRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a named pinset",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !pinsetStore.Remove(args[0]) {
			return fmt.Errorf("pinset %q not found", args[0])
		}
		fmt.Fprintf(cmd.OutOrStdout(), "pinset %q removed\n", args[0])
		return nil
	},
}

var pinsetCheckCmd = &cobra.Command{
	Use:   "check <name> <path>",
	Short: "Check whether a path belongs to a pinset",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, path := args[0], args[1]
		if pinsetStore.Contains(name, path) {
			fmt.Fprintf(cmd.OutOrStdout(), "path %q is in pinset %q\n", path, name)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "path %q is NOT in pinset %q\n", path, name)
		}
		return nil
	},
}

var pinsetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all pinsets",
	RunE: func(cmd *cobra.Command, args []string) error {
		entries := pinsetStore.Entries()
		if len(entries) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "no pinsets defined")
			return nil
		}
		for _, e := range entries {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", e.Name, strings.Join(e.Paths, ", "))
		}
		return nil
	},
}

func init() {
	pinsetCmd.AddCommand(pinsetAddCmd)
	pinsetCmd.AddCommand(pinsetRemoveCmd)
	pinsetCmd.AddCommand(pinsetCheckCmd)
	pinsetCmd.AddCommand(pinsetListCmd)
	rootCmd.AddCommand(pinsetCmd)
	_ = os.Stderr
}
