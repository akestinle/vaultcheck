package audit

import (
	"crypto/sha256"
	"fmt"
	"sort"
)

// Deduplicator removes duplicate secrets from a slice based on their path and key.
type Deduplicator struct {
	// seen tracks fingerprints of already-processed secrets.
	seen map[string]struct{}
}

// NewDeduplicator creates a new Deduplicator instance.
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]struct{}),
	}
}

// Deduplicate returns a new slice containing only unique secrets.
// When duplicates are found the first occurrence (by path+key) is kept.
// The returned slice is sorted by path then key for deterministic output.
func (d *Deduplicator) Deduplicate(secrets []Secret) []Secret {
	result := make([]Secret, 0, len(secrets))

	for _, s := range secrets {
		fp := fingerprint(s.Path, s.Key)
		if _, exists := d.seen[fp]; exists {
			continue
		}
		d.seen[fp] = struct{}{}
		result = append(result, s)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		return result[i].Key < result[j].Key
	})

	return result
}

// Reset clears the internal seen-set so the Deduplicator can be reused.
func (d *Deduplicator) Reset() {
	d.seen = make(map[string]struct{})
}

// fingerprint returns a short deterministic string that identifies a secret
// by its path and key.
func fingerprint(path, key string) string {
	h := sha256.Sum256([]byte(path + "\x00" + key))
	return fmt.Sprintf("%x", h[:8])
}
