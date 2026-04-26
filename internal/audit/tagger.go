package audit

import (
	"strings"
)

// Tag represents a key-value label attached to a secret.
type Tag struct {
	Key   string
	Value string
}

// Tagger assigns tags to secrets based on configurable rules.
type Tagger struct {
	rules []tagRule
}

type tagRule struct {
	pathPrefix string
	tags       []Tag
}

// NewTagger creates a Tagger with no rules.
func NewTagger() *Tagger {
	return &Tagger{}
}

// AddRule registers a rule that applies the given tags to secrets whose
// path starts with pathPrefix.
func (t *Tagger) AddRule(pathPrefix string, tags ...Tag) {
	if pathPrefix == "" || len(tags) == 0 {
		return
	}
	t.rules = append(t.rules, tagRule{pathPrefix: pathPrefix, tags: tags})
}

// Tag applies all matching rules to the provided secrets, returning
// a new slice with the Tags field populated.
func (t *Tagger) Tag(secrets []Secret) []Secret {
	result := make([]Secret, len(secrets))
	for i, s := range secrets {
		tagged := s
		tagged.Tags = append([]Tag(nil), s.Tags...)
		for _, rule := range t.rules {
			if strings.HasPrefix(s.Path, rule.pathPrefix) {
				tagged.Tags = mergeTags(tagged.Tags, rule.tags)
			}
		}
		result[i] = tagged
	}
	return result
}

// mergeTags appends src tags to dst, skipping duplicates by key.
func mergeTags(dst, src []Tag) []Tag {
	existing := make(map[string]struct{}, len(dst))
	for _, t := range dst {
		existing[t.Key] = struct{}{}
	}
	for _, t := range src {
		if _, ok := existing[t.Key]; !ok {
			dst = append(dst, t)
			existing[t.Key] = struct{}{}
		}
	}
	return dst
}
