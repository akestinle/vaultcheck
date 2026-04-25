package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewWebhookSink_EmptyURL(t *testing.T) {
	_, err := NewWebhookSink("", 0)
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestNewWebhookSink_Valid(t *testing.T) {
	ws, err := NewWebhookSink("http://example.com/hook", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ws == nil {
		t.Fatal("expected non-nil WebhookSink")
	}
}

func TestWebhookSink_Send_Success(t *testing.T) {
	var received webhookPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ws, _ := NewWebhookSink(ts.URL, 5*time.Second)
	e := Event{
		Level:     LevelWarn,
		Message:   "secret expiring",
		Timestamp: time.Now().UTC(),
		Meta:      map[string]string{"path": "secret/db"},
	}
	if err := ws.Send(e); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if received.Level != "WARN" {
		t.Errorf("expected WARN, got %s", received.Level)
	}
	if received.Message != "secret expiring" {
		t.Errorf("unexpected message: %s", received.Message)
	}
	if received.Meta["path"] != "secret/db" {
		t.Errorf("unexpected meta path: %s", received.Meta["path"])
	}
}

func TestWebhookSink_Send_NonOKStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	ws, _ := NewWebhookSink(ts.URL, 5*time.Second)
	e := Event{Level: LevelError, Message: "fail", Timestamp: time.Now().UTC()}
	if err := ws.Send(e); err == nil {
		t.Fatal("expected error for non-OK status")
	}
}
