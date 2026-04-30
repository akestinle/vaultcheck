package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WebhookSink posts events as JSON payloads to an HTTP endpoint.
type WebhookSink struct {
	url    string
	client *http.Client
}

// webhookPayload is the JSON body sent to the webhook endpoint.
type webhookPayload struct {
	Level     string            `json:"level"`
	Message   string            `json:"message"`
	Timestamp string            `json:"timestamp"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// NewWebhookSink creates a WebhookSink that posts to url.
// A zero timeout defaults to 10 seconds.
func NewWebhookSink(url string, timeout time.Duration) (*WebhookSink, error) {
	if url == "" {
		return nil, fmt.Errorf("notify: webhook URL must not be empty")
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &WebhookSink{
		url: url,
		client: &http.Client{Timeout: timeout},
	}, nil
}

// Send marshals the event and POSTs it to the configured URL.
func (ws *WebhookSink) Send(e Event) error {
	payload := webhookPayload{
		Level:     string(e.Level),
		Message:   e.Message,
		Timestamp: e.Timestamp.Format(time.RFC3339),
		Meta:      e.Meta,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify: marshal payload: %w", err)
	}
	resp, err := ws.client.Post(ws.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: POST to %s: %w", ws.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// Read up to 256 bytes of the response body to include in the error
		// message, giving callers useful context without unbounded memory use.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		if len(snippet) > 0 {
			return fmt.Errorf("notify: webhook returned status %d: %s", resp.StatusCode, bytes.TrimSpace(snippet))
		}
		return fmt.Errorf("notify: webhook returned status %d", resp.StatusCode)
	}
	return nil
}
