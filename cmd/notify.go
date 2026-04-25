package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"vaultcheck/internal/notify"
)

func init() {
	var (
		webhookURL string
		level      string
		message    string
	)

	notifyCmd := &cobra.Command{
		Use:   "notify",
		Short: "Send a notification event to configured sinks",
		Long: `Send a one-off notification to stdout and/or a webhook endpoint.

Useful for testing notification routing or triggering manual alerts.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if message == "" {
				return fmt.Errorf("--message is required")
			}

			var lvl notify.Level
			switch level {
			case "info":
				lvl = notify.LevelInfo
			case "warn":
				lvl = notify.LevelWarn
			case "error":
				lvl = notify.LevelError
			default:
				return fmt.Errorf("unknown level %q: must be info, warn, or error", level)
			}

			sinks := []notify.Sink{notify.NewWriteSink(os.Stdout)}

			if webhookURL != "" {
				ws, err := notify.NewWebhookSink(webhookURL, 10*time.Second)
				if err != nil {
					return fmt.Errorf("webhook sink: %w", err)
				}
				sinks = append(sinks, ws)
			}

			n, err := notify.NewNotifier(sinks...)
			if err != nil {
				return err
			}

			n.Notify(lvl, message, nil)
			return nil
		},
	}

	notifyCmd.Flags().StringVar(&webhookURL, "webhook", "", "Optional webhook URL to POST the event to")
	notifyCmd.Flags().StringVar(&level, "level", "info", "Notification level: info, warn, error")
	notifyCmd.Flags().StringVar(&message, "message", "", "Notification message (required)")

	rootCmd.AddCommand(notifyCmd)
}
