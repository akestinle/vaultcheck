package audit

import (
	"testing"
	"time"
)

func baseTaggerSecrets() []Secret {
	return []Secret{
		{Path: "secret/prod/db", Key: "password", CreatedAt: time.Now()},
		{Path: "secret/staging/api", Key: "token", CreatedAt: time.Now()},
		{Path: "secret/prod/api", Key: "key", CreatedAt: time.Now()},
	}
}

func TestNewTagger_NotNil(t *testing.T) {
	tr := NewTagger()
	if tr == nil {
		t.Fatal("expected non-nil Tagger")
	}
}

func TestTagger_AddRule_EmptyPrefix_Ignored(t *testing.T) {
	tr := NewTagger()
	tr.AddRule("", Tag{Key: "env", Value: "prod"})
	if len(tr.rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(tr.rules))
	}
}

func TestTagger_AddRule_NoTags_Ignored(t *testing.T) {
	tr := NewTagger()
	tr.AddRule("secret/prod")
	if len(tr.rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(tr.rules))
	}
}

func TestTagger_Tag_MatchingPrefix(t *testing.T) {
	tr := NewTagger()
	tr.AddRule("secret/prod", Tag{Key: "env", Value: "production"})

	secrets := baseTaggerSecrets()
	result := tr.Tag(secrets)

	if len(result[0].Tags) != 1 || result[0].Tags[0].Value != "production" {
		t.Errorf("expected prod tag on first secret, got %+v", result[0].Tags)
	}
	if len(result[1].Tags) != 0 {
		t.Errorf("expected no tags on staging secret, got %+v", result[1].Tags)
	}
	if len(result[2].Tags) != 1 {
		t.Errorf("expected prod tag on third secret, got %+v", result[2].Tags)
	}
}

func TestTagger_Tag_NoDuplicateKeys(t *testing.T) {
	tr := NewTagger()
	tr.AddRule("secret/prod", Tag{Key: "env", Value: "production"})
	tr.AddRule("secret/prod", Tag{Key: "env", Value: "prod-duplicate"})

	secrets := []Secret{{Path: "secret/prod/db", Key: "pass"}}
	result := tr.Tag(secrets)

	envTags := 0
	for _, tag := range result[0].Tags {
		if tag.Key == "env" {
			envTags++
		}
	}
	if envTags != 1 {
		t.Errorf("expected exactly 1 env tag, got %d", envTags)
	}
}

func TestTagger_Tag_PreservesExistingTags(t *testing.T) {
	tr := NewTagger()
	tr.AddRule("secret/prod", Tag{Key: "team", Value: "platform"})

	secrets := []Secret{
		{Path: "secret/prod/db", Tags: []Tag{{Key: "owner", Value: "alice"}}},
	}
	result := tr.Tag(secrets)

	if len(result[0].Tags) != 2 {
		t.Errorf("expected 2 tags, got %d: %+v", len(result[0].Tags), result[0].Tags)
	}
}

func TestTagger_Tag_OriginalUnmodified(t *testing.T) {
	tr := NewTagger()
	tr.AddRule("secret/", Tag{Key: "scanned", Value: "true"})

	original := []Secret{{Path: "secret/prod/db", Tags: nil}}
	_ = tr.Tag(original)

	if len(original[0].Tags) != 0 {
		t.Error("original secret should not be mutated")
	}
}
