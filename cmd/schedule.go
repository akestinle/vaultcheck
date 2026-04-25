package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"vaultcheck/internal/audit"
)

var (
	scheduleInterval  time.Duration
	scheduleRunOnce   bool
	schedulePrefix    string
	scheduleExclude   []string
	scheduleMaxAge    int
	scheduleOutputFmt string
)

var scheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Run periodic audit scans on a fixed interval",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vaultClientFromContext(cmd.Context())
		if err != nil {
			return fmt.Errorf("vault client: %w", err)
		}

		scanner, err := audit.NewScanner(client)
		if err != nil {
			return fmt.Errorf("scanner: %w", err)
		}

		sched := audit.Schedule{
			Interval: scheduleInterval,
			RunOnce:  scheduleRunOnce,
		}

		opts := audit.ScanOptions{
			PathPrefix:   schedulePrefix,
			MaxAgeDays:   scheduleMaxAge,
			ExcludePaths: scheduleExclude,
		}

		scheduler, err := audit.NewScheduler(scanner, sched, func(r *audit.Report) error {
			switch scheduleOutputFmt {
			case "json":
				return r.WriteJSON(os.Stdout)
			default:
				return r.WriteTable(os.Stdout)
			}
		})
		if err != nil {
			return fmt.Errorf("scheduler: %w", err)
		}

		return scheduler.Run(cmd.Context(), opts)
	},
}

func init() {
	rootCmd.AddCommand(scheduleCmd)
	scheduleCmd.Flags().DurationVar(&scheduleInterval, "interval", 1*time.Hour, "scan interval (e.g. 30m, 2h)")
	scheduleCmd.Flags().BoolVar(&scheduleRunOnce, "once", false, "run a single scan and exit")
	scheduleCmd.Flags().StringVar(&schedulePrefix, "prefix", "", "restrict scan to path prefix")
	scheduleCmd.Flags().StringSliceVar(&scheduleExclude, "exclude", nil, "paths to exclude from scan")
	scheduleCmd.Flags().IntVar(&scheduleMaxAge, "max-age", 0, "flag secrets older than N days (0 = disabled)")
	scheduleCmd.Flags().StringVar(&scheduleOutputFmt, "output", "table", "output format: table or json")
}
