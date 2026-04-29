package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vaultcheck/internal/audit"
)

var watchlist = audit.NewWatchlist()

func init() {
	watchlistCmd := &cobra.Command{
		Use:   "watchlist",
		Short: "Manage the secret watchlist",
	}

	addCmd := &cobra.Command{
		Use:   "add <path>",
		Short: "Add a secret path to the watchlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reason, _ := cmd.Flags().GetString("reason")
			alert, _ := cmd.Flags().GetBool("alert")
			if err := watchlist.Add(args[0], reason, alert); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added %s to watchlist\n", args[0])
			return nil
		},
	}
	addCmd.Flags().String("reason", "", "reason for watching this path")
	addCmd.Flags().Bool("alert", false, "alert when the secret changes")

	removeCmd := &cobra.Command{
		Use:   "remove <path>",
		Short: "Remove a secret path from the watchlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !watchlist.Remove(args[0]) {
				return fmt.Errorf("%s not found in watchlist", args[0])
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s from watchlist\n", args[0])
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all watched secret paths",
		RunE: func(cmd *cobra.Command, args []string) error {
			audit.WriteWatchlist(watchlist.Entries(), cmd.OutOrStdout())
			return nil
		},
	}

	checkCmd := &cobra.Command{
		Use:   "check <path>",
		Short: "Check whether a path is on the watchlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if watchlist.Contains(args[0]) {
				fmt.Fprintf(cmd.OutOrStdout(), "%s is on the watchlist\n", args[0])
			} else {
				fmt.Fprintf(os.Stderr, "%s is NOT on the watchlist\n", args[0])
				os.Exit(1)
			}
			return nil
		},
	}

	watchlistCmd.AddCommand(addCmd, removeCmd, listCmd, checkCmd)
	rootCmd.AddCommand(watchlistCmd)
}
