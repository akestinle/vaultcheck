package audit

import (
	"fmt"
	"io"
	"sort"
	"time"
)

// PruneOptions controls which secrets are considered for pruning.
type PruneOptions struct {
	// MaxAgeDays removes secrets older than this many days. Zero means no age limit.
	MaxAgeDays int
	// DryRun reports what would be pruned without removing anything.
	DryRun bool
	// PathPrefixes restricts pruning to secrets under these prefixes.
	PathPrefixes []string
}

// PruneResult holds the outcome of a prune operation.
type PruneResult struct {
	Pruned  []Secret
	Retained []Secret
}

// Pruner evaluates secrets against a policy and marks them for removal.
type Pruner struct {
	opts PruneOptions
	now  time.Time
}

// NewPruner creates a Pruner with the given options.
func NewPruner(opts PruneOptions) *Pruner {
	return &Pruner{opts: opts, now: time.Now().UTC()}
}

// Prune partitions secrets into pruned and retained sets.
func (p *Pruner) Prune(secrets []Secret) PruneResult {
	var result PruneResult
	for _, s := range secrets {
		if p.shouldPrune(s) {
			result.Pruned = append(result.Pruned, s)
		} else {
			result.Retained = append(result.Retained, s)
		}
	}
	sort.Slice(result.Pruned, func(i, j int) bool {
		return result.Pruned[i].Path < result.Pruned[j].Path
	})
	sort.Slice(result.Retained, func(i, j int) bool {
		return result.Retained[i].Path < result.Retained[j].Path
	})
	return result
}

func (p *Pruner) shouldPrune(s Secret) bool {
	if len(p.opts.PathPrefixes) > 0 {
		matched := false
		for _, pfx := range p.opts.PathPrefixes {
			if len(s.Path) >= len(pfx) && s.Path[:len(pfx)] == pfx {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if p.opts.MaxAgeDays > 0 {
		age := p.now.Sub(s.UpdatedAt).Hours() / 24
		return age > float64(p.opts.MaxAgeDays)
	}
	return false
}

// WritePruneResult writes a human-readable prune report to w.
func WritePruneResult(w io.Writer, r PruneResult, dryRun bool) {
	prefix := "PRUNED"
	if dryRun {
		prefix = "WOULD PRUNE"
	}
	fmt.Fprintf(w, "%-14s  %s\n", "STATUS", "PATH")
	for _, s := range r.Pruned {
		fmt.Fprintf(w, "%-14s  %s\n", prefix, s.Path)
	}
	for _, s := range r.Retained {
		fmt.Fprintf(w, "%-14s  %s\n", "RETAINED", s.Path)
	}
	fmt.Fprintf(w, "\nTotal pruned: %d  retained: %d\n", len(r.Pruned), len(r.Retained))
}
