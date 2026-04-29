package audit

import (
	"regexp"
	"strings"
)

// Classification represents a sensitivity level for a secret.
type Classification string

const (
	ClassificationPublic       Classification = "public"
	ClassificationInternal     Classification = "internal"
	ClassificationConfidential Classification = "confidential"
	ClassificationSecret       Classification = "secret"
)

// classifierRule maps a compiled pattern to a classification.
type classifierRule struct {
	pattern        *regexp.Regexp
	classification Classification
}

// Classifier assigns a Classification to secrets based on path or key patterns.
type Classifier struct {
	rules []classifierRule
	defaultClass Classification
}

// NewClassifier returns a Classifier with a default classification of internal.
func NewClassifier() *Classifier {
	return &Classifier{defaultClass: ClassificationInternal}
}

// SetDefault overrides the fallback classification used when no rule matches.
func (c *Classifier) SetDefault(class Classification) {
	c.defaultClass = class
}

// AddRule registers a regex pattern and the classification to apply when it
// matches a secret's Path. Patterns are evaluated in insertion order; the
// first match wins.
func (c *Classifier) AddRule(pattern string, class Classification) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	c.rules = append(c.rules, classifierRule{pattern: re, classification: class})
	return nil
}

// Classify returns the Classification for a single secret.
func (c *Classifier) Classify(s Secret) Classification {
	path := strings.ToLower(s.Path)
	for _, r := range c.rules {
		if r.pattern.MatchString(path) {
			return r.classification
		}
	}
	return c.defaultClass
}

// ClassifyAll annotates each secret with a "classification" tag derived from
// the registered rules and returns a new slice. Original secrets are not
// mutated.
func (c *Classifier) ClassifyAll(secrets []Secret) []Secret {
	out := make([]Secret, len(secrets))
	for i, s := range secrets {
		copy := s
		if copy.Tags == nil {
			copy.Tags = make(map[string]string)
		} else {
			tags := make(map[string]string, len(s.Tags))
			for k, v := range s.Tags {
				tags[k] = v
			}
			copy.Tags = tags
		}
		copy.Tags["classification"] = string(c.Classify(s))
		out[i] = copy
	}
	return out
}
