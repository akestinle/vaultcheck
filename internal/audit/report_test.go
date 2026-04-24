package audit_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/example/vaultcheck/internal/audit"
)

func sampleSecrets() []audit.SecretMeta {
	return []audit.SecretMeta{
		{Path: "app/db", Version: 2, Keys: []string{"1", "2"}},
		{Path: "app/api", Version: 5, Keys: []string{"1", "2", "3", "4", "5"}},
	}
}

func TestNewReport_Fields(t *testing.T) {
	r := audit.NewReport("secret", sampleSecrets())
	assert.Equal(t, "secret", r.Mount)
	assert.Equal(t, 2, r.TotalPaths)
	assert.False(t, r.GeneratedAt.IsZero())
}

func TestReport_WriteJSON(t *testing.T) {
	r := audit.NewReport("secret", sampleSecrets())
	var buf bytes.Buffer
	err := r.WriteJSON(&buf)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, `"mount": "secret"`)
	assert.Contains(t, out, `"total_paths": 2`)
	assert.Contains(t, out, `"app/db"`)
}

func TestReport_WriteTable(t *testing.T) {
	r := audit.NewReport("secret", sampleSecrets())
	var buf bytes.Buffer
	err := r.WriteTable(&buf)
	require.NoError(t, err)
	out := buf.String()
	assert.True(t, strings.Contains(out, "app/db"))
	assert.True(t, strings.Contains(out, "app/api"))
	assert.True(t, strings.Contains(out, "PATH"))
}

func TestReport_WriteTable_Empty(t *testing.T) {
	r := audit.NewReport("secret", nil)
	var buf bytes.Buffer
	err := r.WriteTable(&buf)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "PATH")
}
