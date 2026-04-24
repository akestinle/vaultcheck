package rotation_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/user/vaultcheck/internal/rotation"
)

// stubGenerator always returns a fixed payload or a configured error.
type stubGenerator struct{ err error }

func (s *stubGenerator) Generate(_ string) (map[string]interface{}, error) {
	if s.err != nil {
		return nil, s.err
	}
	return map[string]interface{}{"value": "rotated"}, nil
}

func newTestVaultClient(t *testing.T, handler http.Handler) *api.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("api.NewClient: %v", err)
	}
	client.SetToken("test-token")
	return client
}

func TestNewRotator_NilClient(t *testing.T) {
	_, err := rotation.NewRotator(nil, &stubGenerator{})
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestNewRotator_NilGenerator(t *testing.T) {
	client := newTestVaultClient(t, http.NotFoundHandler())
	_, err := rotation.NewRotator(client, nil)
	if err == nil {
		t.Fatal("expected error for nil generator")
	}
}

func TestRotator_Rotate_Success(t *testing.T) {
	client := newTestVaultClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	rot, err := rotation.NewRotator(client, &stubGenerator{})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	results := rot.Rotate(context.Background(), []string{"secret/data/foo"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Success {
		t.Errorf("expected success, got error: %v", results[0].Error)
	}
}

func TestRotator_Rotate_GeneratorError(t *testing.T) {
	client := newTestVaultClient(t, http.NotFoundHandler())
	gen := &stubGenerator{err: errors.New("entropy failure")}
	rot, _ := rotation.NewRotator(client, gen)
	results := rot.Rotate(context.Background(), []string{"secret/data/bar"})
	if results[0].Success {
		t.Error("expected failure due to generator error")
	}
}
