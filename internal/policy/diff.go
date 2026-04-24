package policy

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// PolicyMap represents a set of Vault policies keyed by name.
type PolicyMap map[string]string

// DiffResult holds the result of comparing two PolicyMaps.
type DiffResult struct {
	Added   []string
	Removed []string
	Changed []PolicyChange
}

// PolicyChange describes a policy whose content has changed.
type PolicyChange struct {
	Name   string
	OldHCL string
	NewHCL string
}

// IsEmpty returns true when there are no differences.
func (d *DiffResult) IsEmpty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// Diff compares two PolicyMaps and returns a DiffResult.
func Diff(baseline, current PolicyMap) *DiffResult {
	result := &DiffResult{}

	for name, curHCL := range current {
		baseHCL, exists := baseline[name]
		if !exists {
			result.Added = append(result.Added, name)
		} else if strings.TrimSpace(curHCL) != strings.TrimSpace(baseHCL) {
			result.Changed = append(result.Changed, PolicyChange{
				Name:   name,
				OldHCL: baseHCL,
				NewHCL: curHCL,
			})
		}
	}

	for name := range baseline {
		if _, exists := current[name]; !exists {
			result.Removed = append(result.Removed, name)
		}
	}

	sort.Strings(result.Added)
	sort.Strings(result.Removed)
	sort.Slice(result.Changed, func(i, j int) bool {
		return result.Changed[i].Name < result.Changed[j].Name
	})

	return result
}

// WriteDiff writes a human-readable diff report to w.
func WriteDiff(w io.Writer, d *DiffResult) {
	if d.IsEmpty() {
		fmt.Fprintln(w, "No policy changes detected.")
		return
	}

	for _, name := range d.Added {
		fmt.Fprintf(w, "[+] ADDED   %s\n", name)
	}
	for _, name := range d.Removed {
		fmt.Fprintf(w, "[-] REMOVED %s\n", name)
	}
	for _, ch := range d.Changed {
		fmt.Fprintf(w, "[~] CHANGED %s\n", ch.Name)
		fmt.Fprintf(w, "    --- old\n%s\n", indent(ch.OldHCL))
		fmt.Fprintf(w, "    +++ new\n%s\n", indent(ch.NewHCL))
	}
}

func indent(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range lines {
		lines[i] = "    " + l
	}
	return strings.Join(lines, "\n")
}
