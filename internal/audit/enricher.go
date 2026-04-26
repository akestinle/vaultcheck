package audit

import (
	"fmt"
	"strings"
	"time"
)

// EnrichmentSource provides additional metadata for secrets during enrichment.
type EnrichmentSource interface {
	// Lookup returns metadata key-value pairs for the given secret path.
	// Returns an empty map if no metadata is available.
	Lookup(path string) map[string]string
}

// Enricher attaches additional metadata to scanned secrets, such as owner
// labels, team assignments, or environment tags derived from path conventions
// or an external source.
type Enricher struct {
	source   EnrichmentSource
	pathTags map[string]string // prefix -> tag value applied as "env" label
}

// NewEnricher constructs an Enricher. source may be nil, in which case only
// path-based tag inference is performed. pathTags maps path prefixes to
// environment labels (e.g. "secret/prod/" -> "production").
func NewEnricher(source EnrichmentSource, pathTags map[string]string) *Enricher {
	if pathTags == nil {
		pathTags = make(map[string]string)
	}
	return &Enricher{
		source:   source,
		pathTags: pathTags,
	}
}

// Enrich iterates over the provided secrets and returns a new slice with
// metadata fields populated. The original secrets are not modified.
func (e *Enricher) Enrich(secrets []Secret) []Secret {
	enriched := make([]Secret, 0, len(secrets))
	for _, s := range secrets {
		copy := s
		if copy.Metadata == nil {
			copy.Metadata = make(map[string]string)
		} else {
			// Shallow-copy the map so we don't mutate the original.
			merged := make(map[string]string, len(s.Metadata))
			for k, v := range s.Metadata {
				merged[k] = v
			}
			copy.Metadata = merged
		}

		// Infer environment tag from path prefix.
		if env := e.inferEnv(copy.Path); env != "" {
			if _, exists := copy.Metadata["env"]; !exists {
				copy.Metadata["env"] = env
			}
		}

		// Infer owner segment from path convention: second path segment is owner.
		if owner := inferOwner(copy.Path); owner != "" {
			if _, exists := copy.Metadata["owner"]; !exists {
				copy.Metadata["owner"] = owner
			}
		}

		// Attach enriched_at timestamp.
		copy.Metadata["enriched_at"] = time.Now().UTC().Format(time.RFC3339)

		// Overlay any metadata from the external source.
		if e.source != nil {
			for k, v := range e.source.Lookup(copy.Path) {
				copy.Metadata[k] = v
			}
		}

		enriched = append(enriched, copy)
	}
	return enriched
}

// inferEnv returns the environment label for the given path by matching
// registered path-tag prefixes (longest match wins).
func (e *Enricher) inferEnv(path string) string {
	best := ""
	bestTag := ""
	for prefix, tag := range e.pathTags {
		if strings.HasPrefix(path, prefix) && len(prefix) > len(best) {
			best = prefix
			bestTag = tag
		}
	}
	return bestTag
}

// inferOwner extracts the second non-empty path segment as a conventional
// owner identifier (e.g. "secret/payments/db-pass" -> "payments").
func inferOwner(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// StaticEnrichmentSource is an EnrichmentSource backed by an in-memory map
// keyed by exact secret path.
type StaticEnrichmentSource struct {
	data map[string]map[string]string
}

// NewStaticEnrichmentSource constructs a StaticEnrichmentSource from the
// provided map. The outer key is the secret path; the inner map holds
// arbitrary metadata key-value pairs.
func NewStaticEnrichmentSource(data map[string]map[string]string) (*StaticEnrichmentSource, error) {
	if data == nil {
		return nil, fmt.Errorf("enrichment data map must not be nil")
	}
	return &StaticEnrichmentSource{data: data}, nil
}

// Lookup returns the metadata for the given path, or an empty map.
func (s *StaticEnrichmentSource) Lookup(path string) map[string]string {
	if m, ok := s.data[path]; ok {
		return m
	}
	return map[string]string{}
}
