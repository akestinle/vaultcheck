package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewStreamer_NilScanner(t *testing.T) {
	_, err := NewStreamer(nil, ScanOptions{}, 0)
	if !errors.Is(err, ErrNilScanner) {
		t.Fatalf("expected ErrNilScanner, got %v", err)
	}
}

func TestNewStreamer_Valid(t *testing.T) {
	ts := newTestVaultServer(t)
	client := newTestVaultClient(t, ts.URL)
	scanner, _ := NewScanner(client)
	str, err := NewStreamer(scanner, ScanOptions{}, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if str == nil {
		t.Fatal("expected non-nil Streamer")
	}
}

func TestStreamer_Stream_Empty(t *testing.T) {
	ts := newTestVaultServer(t)
	client := newTestVaultClient(t, ts.URL)
	scanner, _ := NewScanner(client)
	str, _ := NewStreamer(scanner, ScanOptions{}, 4)

	ctx := context.Background()
	ch := str.Stream(ctx)
	var events []StreamEvent
	for ev := range ch {
		events = append(events, ev)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}
}

func TestStreamer_Stream_ReceivesSecrets(t *testing.T) {
	secrets := []Secret{
		{Path: "secret/a", Key: "token", Value: "abc", UpdatedAt: time.Now()},
		{Path: "secret/b", Key: "pass", Value: "xyz", UpdatedAt: time.Now()},
	}
	scanner := &Scanner{secrets: secrets}
	str, _ := NewStreamer(scanner, ScanOptions{}, 4)

	ctx := context.Background()
	ch := str.Stream(ctx)
	var received []StreamEvent
	for ev := range ch {
		received = append(received, ev)
	}
	if len(received) != 2 {
		t.Fatalf("expected 2 events, got %d", len(received))
	}
	if received[0].Index != 0 || received[1].Index != 1 {
		t.Error("unexpected event indices")
	}
}

func TestStreamer_Stream_CancelledContext(t *testing.T) {
	secrets := make([]Secret, 20)
	for i := range secrets {
		secrets[i] = Secret{Path: "secret/x", Key: "k", Value: "v", UpdatedAt: time.Now()}
	}
	scanner := &Scanner{secrets: secrets}
	str, _ := NewStreamer(scanner, ScanOptions{}, 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch := str.Stream(ctx)
	var count int
	for range ch {
		count++
	}
	// With cancelled context we expect far fewer than 20 events.
	if count >= 20 {
		t.Errorf("expected context cancellation to stop stream, got %d events", count)
	}
}

func TestStreamer_StreamWithInterval_Delivers(t *testing.T) {
	secrets := []Secret{
		{Path: "secret/a", Key: "k", Value: "v", UpdatedAt: time.Now()},
	}
	scanner := &Scanner{secrets: secrets}
	str, _ := NewStreamer(scanner, ScanOptions{}, 2)

	ctx := context.Background()
	ch := str.StreamWithInterval(ctx, 0)
	var events []StreamEvent
	for ev := range ch {
		events = append(events, ev)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}
