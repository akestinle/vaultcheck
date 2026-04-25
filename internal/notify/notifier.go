package notify

import (
	"fmt"
	"io"
	"os"
	"time"
)

// Level represents the severity of a notification.
type Level string

const (
	LevelInfo  Level = "INFO"
	LevelWarn  Level = "WARN"
	LevelError Level = "ERROR"
)

// Event holds the details of a single notification event.
type Event struct {
	Level     Level
	Message   string
	Timestamp time.Time
	Meta      map[string]string
}

// Sink is the interface implemented by notification backends.
type Sink interface {
	Send(e Event) error
}

// Notifier dispatches events to one or more sinks.
type Notifier struct {
	sinks []Sink
}

// NewNotifier creates a Notifier with the provided sinks.
// At least one sink is required.
func NewNotifier(sinks ...Sink) (*Notifier, error) {
	if len(sinks) == 0 {
		return nil, fmt.Errorf("notify: at least one sink is required")
	}
	return &Notifier{sinks: sinks}, nil
}

// Notify sends an event at the given level to all registered sinks.
// Errors from individual sinks are printed to stderr but do not abort delivery.
func (n *Notifier) Notify(level Level, message string, meta map[string]string) {
	e := Event{
		Level:     level,
		Message:   message,
		Timestamp: time.Now().UTC(),
		Meta:      meta,
	}
	for _, s := range n.sinks {
		if err := s.Send(e); err != nil {
			fmt.Fprintf(os.Stderr, "notify: sink error: %v\n", err)
		}
	}
}

// WriteSink is a Sink that writes human-readable events to an io.Writer.
type WriteSink struct {
	w io.Writer
}

// NewWriteSink creates a WriteSink backed by w.
func NewWriteSink(w io.Writer) *WriteSink {
	return &WriteSink{w: w}
}

// Send formats and writes the event to the underlying writer.
func (ws *WriteSink) Send(e Event) error {
	_, err := fmt.Fprintf(ws.w, "[%s] %s %s\n", e.Level, e.Timestamp.Format(time.RFC3339), e.Message)
	return err
}
