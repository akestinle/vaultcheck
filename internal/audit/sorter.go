package audit

import (
	"sort"
	"strings"
)

// SortField represents a field by which secrets can be sorted.
type SortField string

const (
	SortByPath    SortField = "path"
	SortByAge     SortField = "age"
	SortByKey     SortField = "key"
	SortByExpiry  SortField = "expiry"
)

// SortOrder represents ascending or descending sort order.
type SortOrder string

const (
	SortAsc  SortOrder = "asc"
	SortDesc SortOrder = "desc"
)

// SortOptions configures how secrets are sorted.
type SortOptions struct {
	Field SortField
	Order SortOrder
}

// NewSortOptions returns SortOptions with sensible defaults.
func NewSortOptions(field SortField, order SortOrder) SortOptions {
	if field == "" {
		field = SortByPath
	}
	if order == "" {
		order = SortAsc
	}
	return SortOptions{Field: field, Order: order}
}

// Sort returns a new slice of secrets sorted according to opts.
func Sort(secrets []Secret, opts SortOptions) []Secret {
	out := make([]Secret, len(secrets))
	copy(out, secrets)

	sort.SliceStable(out, func(i, j int) bool {
		less := compareSecrets(out[i], out[j], opts.Field)
		if opts.Order == SortDesc {
			return !less
		}
		return less
	})
	return out
}

func compareSecrets(a, b Secret, field SortField) bool {
	switch field {
	case SortByAge:
		return a.AgeDays() > b.AgeDays()
	case SortByKey:
		return strings.ToLower(a.Key) < strings.ToLower(b.Key)
	case SortByExpiry:
		if a.ExpiresAt == nil && b.ExpiresAt == nil {
			return false
		}
		if a.ExpiresAt == nil {
			return false
		}
		if b.ExpiresAt == nil {
			return true
		}
		return a.ExpiresAt.Before(*b.ExpiresAt)
	default: // SortByPath
		return strings.ToLower(a.Path) < strings.ToLower(b.Path)
	}
}
