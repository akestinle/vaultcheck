package notify

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// errSink is a Sink that always returns an error, used to verify resilience.
type errSink struct{}

func (e *errSink) Send(_ Event) error { return errors.New("sink failure") }

// captureSink records every event it receives.
type captureSink struct{ events []Event }

func (c *captureSink) Send(e Event) error {
	c.events = append(c.events, e)
	return nil
}

func TestNewNotifier_NoSinks(t *testing.T) {
	_, err := NewNotifier()
	if err == nil {
		t.Fatal("expected error with no sinks")
	}
}

func TestNewNotifier_Valid(t *testing.T) {
	n, err := NewNotifier(&captureSink{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil notifier")
	}
}

func TestNotifier_Notify_Delivered(t *testing.T) {
	cap := &captureSink{}
	n, _ := NewNotifier(cap)
	n.Notify(LevelInfo, "rotation complete", map[string]string{"path": "secret/foo"})
	if len(cap.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(cap.events))
	}
	if cap.events[0].Level != LevelInfo {
		t.Errorf("expected INFO, got %s", cap.events[0].Level)
	}
	if cap.events[0].Message != "rotation complete" {
		t.Errorf("unexpected message: %s", cap.events[0].Message)
	}
}

func TestNotifier_Notify_MultiSink(t *testing.T) {
	c1, c2 := &captureSink{}, &captureSink{}
	n, _ := NewNotifier(c1, c2)
	n.Notify(LevelWarn, "expiry soon", nil)
	if len(c1.events) != 1 || len(c2.events) != 1 {
		t.Fatal("expected both sinks to receive the event")
	}
}

func TestNotifier_Notify_SinkError_NoAbort(t *testing.T) {
	c := &captureSink{}
	n, _ := NewNotifier(&errSink{}, c)
	// Should not panic; second sink still receives event.
	n.Notify(LevelError, "vault unreachable", nil)
	if len(c.events) != 1 {
		t.Fatal("expected second sink to receive event despite first sink error")
	}
}

func TestWriteSink_Send(t *testing.T) {
	var buf bytes.Buffer
	ws := NewWriteSink(&buf)
	n, _ := NewNotifier(ws)
	n.Notify(LevelInfo, "hello world", nil)
	out := buf.String()
	if !strings.Contains(out, "[INFO]") {
		t.Errorf("expected [INFO] in output, got: %s", out)
	}
	if !strings.Contains(out, "hello world") {
		t.Errorf("expected message in output, got: %s", out)
	}
}
