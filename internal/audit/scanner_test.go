package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
)

func newTestVaultServer(t *testing.T) (*vaultapi.Client, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/secret/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "LIST" || r.URL.Query().Get("list") == "true" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{"mykey"}},
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"value": "s3cr3t"},
		})
	})

	ts := httptest.NewServer(mux)
	cfg := vaultapi.DefaultConfig()
	cfg.Address = ts.URL
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	client.SetToken("test-token")
	return client, ts
}

func TestNewScanner_NotNil(t *testing.T) {
	client, ts := newTestVaultServer(t)
	defer ts.Close()
	s, err := NewScanner(client.Logical(), "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestScanner_Scan_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/empty/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := vaultapi.DefaultConfig()
	cfg.Address = ts.URL
	client, _ := vaultapi.NewClient(cfg)
	client.SetToken("t")

	s, _ := NewScanner(client.Logical(), "empty")
	results, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected empty, got %d", len(results))
	}
}

func TestScanner_Scan_SingleSecret(t *testing.T) {
	client, ts := newTestVaultServer(t)
	defer ts.Close()

	s, _ := NewScanner(client.Logical(), "secret")
	results, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
}
