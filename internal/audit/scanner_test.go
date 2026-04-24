package audit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/example/vaultcheck/internal/audit"
)

func newTestVaultServer(t *testing.T, routes map[string]interface{}) (*httptest.Server, *vaultapi.Client) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": v})
	}))
	cfg := vaultapi.DefaultConfig()
	cfg.Address = ts.URL
	client, err := vaultapi.NewClient(cfg)
	require.NoError(t, err)
	client.SetToken("test-token")
	return ts, client
}

func TestScanner_Scan_Empty(t *testing.T) {
	ts, client := newTestVaultServer(t, map[string]interface{}{
		"/v1/secret/metadata/": nil,
	})
	defer ts.Close()

	s := audit.NewScanner(client, "secret")
	results, err := s.Scan(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanner_Scan_SingleSecret(t *testing.T) {
	routes := map[string]interface{}{
		"/v1/secret/metadata/": map[string]interface{}{"keys": []interface{}{"myapp"}},
		"/v1/secret/metadata/myapp": map[string]interface{}{
			"current_version": float64(3),
			"versions":        map[string]interface{}{"1": nil, "2": nil, "3": nil},
		},
	}
	ts, client := newTestVaultServer(t, routes)
	defer ts.Close()

	s := audit.NewScanner(client, "secret")
	results, err := s.Scan(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "myapp", results[0].Path)
	assert.Equal(t, 3, results[0].Version)
	assert.Len(t, results[0].Keys, 3)
}

func TestNewScanner_NotNil(t *testing.T) {
	cfg := vaultapi.DefaultConfig()
	client, err := vaultapi.NewClient(cfg)
	require.NoError(t, err)
	s := audit.NewScanner(client, "secret")
	assert.NotNil(t, s)
}
