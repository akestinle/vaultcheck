package audit

import "time"

// Secret represents a single secret entry discovered during an audit scan.
type Secret struct {
	// Path is the Vault KV path where the secret resides.
	Path string `json:"path"`

	// Key is the field name within the secret.
	Key string `json:"key"`

	// CreatedAt is when the secret version was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is the optional expiry time for the secret.
	// Zero value means no expiry is set.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Metadata holds arbitrary key/value pairs from Vault metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// AgeDays returns how many full days old the secret is relative to now.
func (s Secret) AgeDays() int {
	return int(time.Since(s.CreatedAt).Hours() / 24)
}

// IsExpired reports whether the secret has a non-zero expiry that is in the past.
func (s Secret) IsExpired() bool {
	return !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt)
}

// ExpiresWithin reports whether the secret expires within the given duration.
func (s Secret) ExpiresWithin(d time.Duration) bool {
	if s.ExpiresAt.IsZero() {
		return false
	}
	return time.Until(s.ExpiresAt) <= d
}
