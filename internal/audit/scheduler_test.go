package audit

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewScheduler_NilScanner(t *testing.T) {
	_, err := NewScheduler(nil, Schedule{RunOnce: true}, func(*Report) error { return nil })
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}

func TestNewScheduler_NilCallback(t *testing.T) {
	ts := newTestVaultServer(t)
	scanner, _ := NewScanner(ts.client)
	_, err := NewScheduler(scanner, Schedule{RunOnce: true}, nil)
	if err == nil {
		t.Fatal("expected error for nil callback")
	}
}

func TestNewScheduler_ZeroIntervalRecurring(t *testing.T) {
	ts := newTestVaultServer(t)
	scanner, _ := NewScanner(ts.client)
	_, err := NewScheduler(scanner, Schedule{Interval: 0, RunOnce: false}, func(*Report) error { return nil })
	if err == nil {
		t.Fatal("expected error for zero interval on recurring schedule")
	}
}

func TestScheduler_RunOnce(t *testing.T) {
	ts := newTestVaultServer(t)
	scanner, _ := NewScanner(ts.client)

	var called int32
	sch, err := NewScheduler(scanner, Schedule{RunOnce: true}, func(r *Report) error {
		atomic.AddInt32(&called, 1)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	if err := sch.Run(ctx, ScanOptions{}); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if atomic.LoadInt32(&called) != 1 {
		t.Fatalf("expected callback called once, got %d", called)
	}
}

func TestScheduler_RunRecurring_Cancels(t *testing.T) {
	ts := newTestVaultServer(t)
	scanner, _ := NewScanner(ts.client)

	var called int32
	sch, _ := NewScheduler(scanner, Schedule{Interval: 20 * time.Millisecond}, func(r *Report) error {
		atomic.AddInt32(&called, 1)
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Millisecond)
	defer cancel()

	err := sch.Run(ctx, ScanOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if atomic.LoadInt32(&called) < 2 {
		t.Fatalf("expected at least 2 calls, got %d", called)
	}
}

func TestScheduler_ReportContainsSecrets(t *testing.T) {
	ts := newTestVaultServer(t)
	scanner, _ := NewScanner(ts.client)

	var buf bytes.Buffer
	sch, _ := NewScheduler(scanner, Schedule{RunOnce: true}, func(r *Report) error {
		return r.WriteJSON(&buf)
	})

	if err := sch.Run(context.Background(), ScanOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty report output")
	}
}
