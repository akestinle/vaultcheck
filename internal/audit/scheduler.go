package audit

import (
	"context"
	"fmt"
	"time"
)

// Schedule defines when and how often an audit should run.
type Schedule struct {
	Interval time.Duration
	RunOnce  bool
}

// Scheduler runs periodic audit scans and delivers reports via a callback.
type Scheduler struct {
	scanner  *Scanner
	schedule Schedule
	onReport func(*Report) error
}

// NewScheduler creates a Scheduler with the given scanner, schedule, and report handler.
func NewScheduler(scanner *Scanner, schedule Schedule, onReport func(*Report) error) (*Scheduler, error) {
	if scanner == nil {
		return nil, fmt.Errorf("scanner must not be nil")
	}
	if onReport == nil {
		return nil, fmt.Errorf("onReport callback must not be nil")
	}
	if schedule.Interval <= 0 && !schedule.RunOnce {
		return nil, fmt.Errorf("interval must be positive for recurring schedules")
	}
	return &Scheduler{
		scanner:  scanner,
		schedule: schedule,
		onReport: onReport,
	}, nil
}

// Run starts the scheduler loop. It blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context, opts ScanOptions) error {
	if err := s.runOnce(ctx, opts); err != nil {
		return err
	}
	if s.schedule.RunOnce {
		return nil
	}
	ticker := time.NewTicker(s.schedule.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := s.runOnce(ctx, opts); err != nil {
				return err
			}
		}
	}
}

func (s *Scheduler) runOnce(ctx context.Context, opts ScanOptions) error {
	secrets, err := s.scanner.Scan(ctx, opts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	report := NewReport(secrets)
	return s.onReport(report)
}
