package audit

import (
	"context"
	"time"
)

// StreamEvent represents a single secret emitted during a stream scan.
type StreamEvent struct {
	Secret Secret
	Index  int
	Err    error
}

// Streamer emits secrets one at a time over a channel, useful for large vaults.
type Streamer struct {
	scanner  *Scanner
	options  ScanOptions
	bufSize  int
}

// NewStreamer creates a Streamer backed by the given Scanner.
// bufSize controls the channel buffer (0 = unbuffered).
func NewStreamer(scanner *Scanner, options ScanOptions, bufSize int) (*Streamer, error) {
	if scanner == nil {
		return nil, ErrNilScanner
	}
	if bufSize < 0 {
		bufSize = 0
	}
	return &Streamer{scanner: scanner, options: options, bufSize: bufSize}, nil
}

// Stream scans secrets and sends each one to the returned channel.
// The channel is closed when all secrets have been emitted or ctx is cancelled.
func (s *Streamer) Stream(ctx context.Context) <-chan StreamEvent {
	ch := make(chan StreamEvent, s.bufSize)
	go func() {
		defer close(ch)
		secrets, err := s.scanner.Scan(s.options)
		if err != nil {
			select {
			case ch <- StreamEvent{Err: err}:
			case <-ctx.Done():
			}
			return
		}
		for i, sec := range secrets {
			select {
			case <-ctx.Done():
				return
			case ch <- StreamEvent{Secret: sec, Index: i}:
			}
		}
	}()
	return ch
}

// StreamWithInterval is like Stream but introduces a delay between events.
// Useful for rate-limiting downstream consumers.
func (s *Streamer) StreamWithInterval(ctx context.Context, interval time.Duration) <-chan StreamEvent {
	ch := make(chan StreamEvent, s.bufSize)
	go func() {
		defer close(ch)
		inner := s.Stream(ctx)
		for ev := range inner {
			select {
			case <-ctx.Done():
				return
			case ch <- ev:
			}
			if interval > 0 {
				select {
				case <-time.After(interval):
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch
}
