package audit

import (
	"fmt"
	"io"
	"strings"
)

// HighlightRule defines a pattern and the label to apply when matched.
type HighlightRule struct {
	PathPrefix string
	Label      string
	Color      string // ANSI color code, e.g. "\033[31m" for red
}

// Highlighter annotates secrets with a visual marker based on matching rules.
type Highlighter struct {
	rules []HighlightRule
}

// NewHighlighter returns a new Highlighter with no rules.
func NewHighlighter() *Highlighter {
	return &Highlighter{}
}

// AddRule registers a highlight rule. Rules with empty prefix or label are ignored.
func (h *Highlighter) AddRule(prefix, label, color string) {
	if strings.TrimSpace(prefix) == "" || strings.TrimSpace(label) == "" {
		return
	}
	h.rules = append(h.rules, HighlightRule{
		PathPrefix: prefix,
		Label:      label,
		Color:      color,
	})
}

// Highlight returns a copy of each secret annotated with a highlight label
// based on the first matching rule. Unmatched secrets are returned as-is.
func (h *Highlighter) Highlight(secrets []Secret) []Secret {
	out := make([]Secret, len(secrets))
	for i, s := range secrets {
		out[i] = s
		for _, rule := range h.rules {
			if strings.HasPrefix(s.Path, rule.PathPrefix) {
				if out[i].Tags == nil {
					out[i].Tags = make(map[string]string)
				} else {
					tags := make(map[string]string, len(s.Tags))
					for k, v := range s.Tags {
						tags[k] = v
					}
					out[i].Tags = tags
				}
				out[i].Tags["highlight"] = rule.Label
				break
			}
		}
	}
	return out
}

// WriteHighlights writes a human-readable summary of highlighted secrets to w.
func WriteHighlights(w io.Writer, secrets []Secret) {
	for _, s := range secrets {
		label, ok := s.Tags["highlight"]
		if !ok {
			continue
		}
		fmt.Fprintf(w, "[%s] %s\n", label, s.Path)
	}
}
