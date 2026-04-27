package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultLabelOptions_Empty(t *testing.T) {
	opts := DefaultLabelOptions()
	assert.Empty(t, opts.Rules)
}

func TestLabelOptions_AddRule_Valid(t *testing.T) {
	opts := DefaultLabelOptions()
	opts.AddRule("secret/app", map[string]string{"env": "prod"})
	require.Len(t, opts.Rules, 1)
	assert.Equal(t, "secret/app", opts.Rules[0].Prefix)
	assert.Equal(t, "prod", opts.Rules[0].Labels["env"])
}

func TestLabelOptions_AddRule_EmptyPrefix_Ignored(t *testing.T) {
	opts := DefaultLabelOptions()
	opts.AddRule("", map[string]string{"env": "prod"})
	assert.Empty(t, opts.Rules)
}

func TestLabelOptions_AddRule_EmptyLabels_Ignored(t *testing.T) {
	opts := DefaultLabelOptions()
	opts.AddRule("secret/app", map[string]string{})
	assert.Empty(t, opts.Rules)
}

func TestLabelOptions_BuildLabeler_NotNil(t *testing.T) {
	opts := DefaultLabelOptions()
	l := opts.BuildLabeler()
	require.NotNil(t, l)
}

func TestLabelOptions_BuildLabeler_AppliesRules(t *testing.T) {
	opts := DefaultLabelOptions()
	opts.AddRule("secret/app", map[string]string{"team": "platform"})

	l := opts.BuildLabeler()
	secrets := []Secret{
		{Path: "secret/app/db", Key: "pass"},
		{Path: "secret/infra/tls", Key: "cert"},
	}
	result := l.Label(secrets)

	assert.Equal(t, "platform", result[0].Metadata["team"])
	assert.Empty(t, result[1].Metadata["team"])
}
