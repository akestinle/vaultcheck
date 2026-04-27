package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"vaultcheck/internal/audit"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List audited secrets with sorting and pagination",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vaultClientFromContext(cmd.Context())
		if err != nil {
			return err
		}

		scanner, err := audit.NewScanner(client)
		if err != nil {
			return fmt.Errorf("scanner: %w", err)
		}

		sortField, _ := cmd.Flags().GetString("sort")
		sortOrder, _ := cmd.Flags().GetString("order")
		page, _ := cmd.Flags().GetInt("page")
		pageSize, _ := cmd.Flags().GetInt("page-size")

		secrets, err := scanner.Scan(cmd.Context(), audit.ScanOptions{})
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}

		sorted := audit.Sort(secrets, audit.NewSortOptions(
			audit.SortField(sortField),
			audit.SortOrder(sortOrder),
		))

		paged, err := audit.Paginate(sorted, page, pageSize)
		if err != nil {
			return fmt.Errorf("paginate: %w", err)
		}

		fmt.Fprintf(os.Stdout, "Page %d/%d  (total: %d secrets)\n\n",
			paged.Page, paged.TotalPages, paged.TotalCount)

		for _, s := range paged.Secrets {
			age := strconv.Itoa(s.AgeDays()) + "d"
			expiry := "no-expiry"
			if s.ExpiresAt != nil {
				expiry = s.ExpiresAt.Format("2006-01-02")
			}
			fmt.Fprintf(os.Stdout, "  %-40s  key=%-20s  age=%-6s  expires=%s\n",
				s.Path, s.Key, age, expiry)
		}

		if paged.HasNext {
			fmt.Fprintln(os.Stdout, "\n  (use --page to see more)")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().String("sort", "path", "Sort field: path|age|key|expiry")
	listCmd.Flags().String("order", "asc", "Sort order: asc|desc")
	listCmd.Flags().Int("page", 1, "Page number (1-based)")
	listCmd.Flags().Int("page-size", 20, "Number of secrets per page")
}
