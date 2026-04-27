package audit

import "sort"

// GroupBy defines the field to group secrets by.
type GroupBy string

const (
	GroupByPrefix GroupBy = "prefix"
	GroupByOwner  GroupBy = "owner"
	GroupByTag    GroupBy = "tag"
)

// Group holds a named collection of secrets.
type Group struct {
	Key     string
	Secrets []Secret
}

// Grouper partitions secrets into named groups.
type Grouper struct {
	by GroupBy
}

// NewGrouper returns a Grouper that partitions by the given field.
func NewGrouper(by GroupBy) *Grouper {
	return &Grouper{by: by}
}

// Group partitions the given secrets and returns sorted groups.
func (g *Grouper) Group(secrets []Secret) []Group {
	buckets := make(map[string][]Secret)

	for _, s := range secrets {
		key := g.keyFor(s)
		buckets[key] = append(buckets[key], s)
	}

	groups := make([]Group, 0, len(buckets))
	for k, v := range buckets {
		groups = append(groups, Group{Key: k, Secrets: v})
	}

	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Key < groups[j].Key
	})

	return groups
}

func (g *Grouper) keyFor(s Secret) string {
	switch g.by {
	case GroupByOwner:
		if s.Owner != "" {
			return s.Owner
		}
		return "unknown"
	case GroupByTag:
		if len(s.Tags) > 0 {
			return s.Tags[0]
		}
		return "untagged"
	default: // GroupByPrefix
		return topLevelSegment(s.Path)
	}
}
