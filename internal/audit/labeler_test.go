package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var labelerSecrets = []Secret{
	{Path: "secret/app/db/password", Key: "password"},
	{Path: "secret/infra/tls/cert", Key: "cert"},
	{Path: "secret/app/api/token", Key: "token"},
}

func TestNewLabeler_NotNil(t *testing.T) {
	l := NewLabeler()
	require.NotNil(t, l)
}

func TestLabeler_AddRule_EmptyPrefix_Ignored(t *testing.T) {
	l := NewLabeler()
	l.AddRule("", map[string]string{"env": "prod"})
	assert.Empty(t, l.rules)
}

func TestLabeler_AddRule_NilLabels_Ignored(t *testing.T) {
	l := NewLabeler()
	l.AddRule("secret/app", nil)
	assert.Empty(t, l.rules)
}

func TestLabeler_Label_MatchingPrefix(t *testing.T) {
	l := NewLabeler()
	l.AddRule("secret/app", map[string]string{"team": "platform"})

	result := l.Label(labelerSecrets)
	require.Len(t, result, 3)

	assert.Equal(t, "platform", result[0].Metadata["team"])
	assert.Equal(t, "", result[1].Metadata["team"])
	assert.Equal(t, "platform", result[2].Metadata["team"])
}

func TestLabeler_Label_NoMatchingRules(t *testing.T) {
	l := NewLabeler()
	l.AddRule("secret/other", map[string]string{"env": "staging"})

	result := l.Label(labelerSecrets)
	for _, s := range result {
		assert.Empty(t, s.Metadata["env"])
	}
}

func TestLabeler_Label_LaterRuleOverrides(t *testing.T) {
	l := NewLabeler()
	l.AddRule("secret/app", map[string]string{"env": "dev"})
	l.AddRule("secret/app/db", map[string]string{"env": "prod"})

	result := l.Label(labelerSecrets)
	assert.Equal(t, "prod", result[0].Metadata["env"])
	assert.Equal(t, "dev", result[2].Metadata["env"])
}

func TestLabeler_Label_PreservesExistingMetadata(t *testing.T) {
	secrets := []Secret{
		{Path: "secret/app/db/password", Key: "password", Metadata: map[string]string{"owner": "alice"}},
	}
	l := NewLabeler()
	l.AddRule("secret/app", map[string]string{"team": "platform"})

	result := l.Label(secrets)
	assert.Equal(t, "alice", result[0].Metadata["owner"])
	assert.Equal(t, "platform", result[0].Metadata["team"])
}

func TestLabeler_Label_DoesNotMutateInput(t *testing.T) {
	secrets := []Secret{
		{Path: "secret/app/db/password", Key: "password", Metadata: map[string]string{"owner": "alice"}},
	}
	l := NewLabeler()
	l.AddRule("secret/app", map[string]string{"team": "platform"})

	l.Label(secrets)
	assert.NotContains(t, secrets[0].Metadata, "team")
}
