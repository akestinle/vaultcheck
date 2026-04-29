package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourusername/vaultcheck/internal/audit"
)

var streamCmd = &cobra.Command{
	Use:   "stream",
	Short: "Stream secrets from Vault one at a time",
	Long:  "Scan Vault secrets and emit each one to stdout as it is discovered, useful for large vaults.",
	RunE:  runStream,
}

var (
	streamBufSize    int
	streamInterval  time.Duration
	streamPathPrefix string
)

func init() {
	streamCmd.Flags().IntVar(&streamBufSize, "buf", 16, "channel buffer size")
	streamCmd.Flags().DurationVar(&streamInterval, "interval", 0, "delay between emitted secrets (e.g. 10ms)")
	streamCmd.Flags().StringVar(&streamPathPrefix, "prefix", "", "only stream secrets under this path prefix")
	rootCmd.AddCommand(streamCmd)
}

func runStream(cmd *cobra.Command, _ []string) error {
	vc, err := vaultClientFromContext(cmd.Context())
	if err != nil {
		return err
	}

	scanner, err := audit.NewScanner(vc)
	if err != nil {
		return fmt.Errorf("stream: create scanner: %w", err)
	}

	opts := audit.ScanOptions{PathPrefix: streamPathPrefix}

	str, err := audit.NewStreamer(scanner, opts, streamBufSize)
	if err != nil {
		return fmt.Errorf("stream: create streamer: %w", err)
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	var ch <-chan audit.StreamEvent
	if streamInterval > 0 {
		ch = str.StreamWithInterval(ctx, streamInterval)
	} else {
		ch = str.Stream(ctx)
	}

	count := 0
	for ev := range ch {
		if ev.Err != nil {
			fmt.Fprintf(os.Stderr, "stream error: %v\n", ev.Err)
			return ev.Err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "[%d] %s/%s\n", ev.Index, ev.Secret.Path, ev.Secret.Key)
		count++
	}

	fmt.Fprintf(cmd.OutOrStdout(), "streamed %d secrets\n", count)
	return nil
}
