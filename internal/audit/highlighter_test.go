package audit

import (
	"bytes"
	"strings"
	"testing"
)

var highlighterSecrets = []Secret{
	{Path: "secret/prod/db/password", Value: "s3cr3t"},
	{Path: "secret/dev/api/key", Value: "devkey"},
	{Path: "secret/prod/api/token", Value: "tok"},
	{Path: "secret/staging/cert", Value: "cert"},
}

func TestNewHighlighter_NotNil(t *testing.T) {
	h := NewHighlighter()
	if h == nil {
		t.Fatal("expected non-nil Highlighter")
	}
}

func TestHighlighter_AddRule_EmptyPrefix_Ignored(t *testing.T) {
	h := NewHighlighter()
	h.AddRule("", "critical", "")
	if len(h.rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(h.rules))
	}
}

func TestHighlighter_AddRule_EmptyLabel_Ignored(t *testing.T) {
	h := NewHighlighter()
	h.AddRule("secret/prod", "", "")
	if len(h.rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(h.rules))
	}
}

func TestHighlighter_Highlight_MatchingPrefix(t *testing.T) {
	h := NewHighlighter()
	h.AddRule("secret/prod", "critical", "\033[31m")

	out := h.Highlight(highlighterSecrets)

	for _, s := range out {
		if strings.HasPrefix(s.Path, "secret/prod") {
			if got := s.Tags["highlight"]; got != "critical" {
				t.Errorf("path %s: expected highlight=critical, got %q", s.Path, got)
			}
		} else {
			if _, ok := s.Tags["highlight"]; ok {
				t.Errorf("path %s: should not be highlighted", s.Path)
			}
		}
	}
}

func TestHighlighter_Highlight_FirstRuleWins(t *testing.T) {
	h := NewHighlighter()
	h.AddRule("secret/prod", "critical", "")
	h.AddRule("secret/prod/db", "database", "")

	out := h.Highlight(highlighterSecrets)

	for _, s := range out {
		if s.Path == "secret/prod/db/password" {
			if got := s.Tags["highlight"]; got != "critical" {
				t.Errorf("expected first rule to win, got %q", got)
			}
		}
	}
}

func TestHighlighter_DoesNotMutateOriginal(t *testing.T) {
	h := NewHighlighter()
	h.AddRule("secret/prod", "critical", "")

	orig := make([]Secret, len(highlighterSecrets))
	copy(orig, highlighterSecrets)

	h.Highlight(highlighterSecrets)

	for i, s := range highlighterSecrets {
		if s.Path != orig[i].Path {
			t.Errorf("original mutated at index %d", i)
		}
		if _, ok := s.Tags["highlight"]; ok {
			t.Errorf("original secret at index %d should not have highlight tag", i)
		}
	}
}

func TestWriteHighlights_OnlyHighlighted(t *testing.T) {
	h := NewHighlighter()
	h.AddRule("secret/prod", "critical", "")
	out := h.Highlight(highlighterSecrets)

	var buf bytes.Buffer
	WriteHighlights(&buf, out)

	result := buf.String()
	if !strings.Contains(result, "secret/prod/db/password") {
		t.Error("expected prod/db/password in output")
	}
	if strings.Contains(result, "secret/dev/api/key") {
		t.Error("dev secret should not appear in highlights output")
	}
}
