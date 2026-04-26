package audit

import "time"

// Secret represents a single secret entry retrieved from Vault.
type Secret struct {
	Path      string
	Key       string
	Value     string
	CreatedAt time.Time
	ExpiresAt *time.Time
	Owner     string
	Tags      []Tag
}

// AgeDays returns how many whole days old the secret is relative to now.
func (s Secret) AgeDays() int {
	if s.CreatedAt.IsZero() {
		return 0
	}
	return int(time.Since(s.CreatedAt).Hours() / 24)
}

// IsExpired reports whether the secret has passed its expiry time.
func (s Secret) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}

// ExpiresInDays returns the number of whole days until expiry.
// Returns -1 if no expiry is set, and 0 if already expired.
func (s Secret) ExpiresInDays() int {
	if s.ExpiresAt == nil {
		return -1
	}
	d := time.Until(*s.ExpiresAt)
	if d <= 0 {
		return 0
	}
	return int(d.Hours() / 24)
}
