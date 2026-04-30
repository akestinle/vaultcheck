package audit

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// InspectResult holds the detailed inspection output for a single secret.
type InspectResult struct {
	Secret     Secret
	Agedays    int
	RiskLevel  string
	Tags       []string
	Labels     map[string]string
	Issues     []string
	InspectedAt time.Time
}

// Inspector performs a deep inspection of individual secrets.
type Inspector struct {
	scorer  *Scorer
	tagger  *Tagger
	labeler *Labeler
}

// NewInspector creates an Inspector with the provided scorer, tagger, and labeler.
// scorer, tagger, and labeler may be nil; each step is skipped when nil.
func NewInspector(scorer *Scorer, tagger *Tagger, labeler *Labeler) *Inspector {
	return &Inspector{
		scorer:  scorer,
		tagger:  tagger,
		labeler: labeler,
	}
}

// Inspect performs a full inspection of the given secret and returns an InspectResult.
func (ins *Inspector) Inspect(s Secret) InspectResult {
	r := InspectResult{
		Secret:      s,
		Agedays:     s.AgeDays(),
		InspectedAt: time.Now().UTC(),
	}

	if ins.scorer != nil {
		sc := ins.scorer.Score(s)
		r.RiskLevel = sc.Level
		for _, issue := range sc.Reasons {
			r.Issues = append(r.Issues, issue)
		}
	}

	if ins.tagger != nil {
		tagged := ins.tagger.Tag([]Secret{s})
		if len(tagged) > 0 {
			r.Tags = tagged[0].Tags
		}
	}

	if ins.labeler != nil {
		labeled := ins.labeler.Label([]Secret{s})
		if len(labeled) > 0 {
			r.Labels = labeled[0].Labels
		}
	}

	if s.IsExpired() {
		r.Issues = append(r.Issues, "secret is expired")
	}

	return r
}

// WriteInspectResult writes a human-readable inspection report to w.
func WriteInspectResult(w io.Writer, r InspectResult) {
	fmt.Fprintf(w, "Path:         %s\n", r.Secret.Path)
	fmt.Fprintf(w, "Owner:        %s\n", r.Secret.Owner)
	fmt.Fprintf(w, "Age (days):   %d\n", r.Agedays)
	fmt.Fprintf(w, "Risk Level:   %s\n", r.RiskLevel)
	fmt.Fprintf(w, "Inspected At: %s\n", r.InspectedAt.Format(time.RFC3339))

	if len(r.Tags) > 0 {
		fmt.Fprintf(w, "Tags:         %s\n", strings.Join(r.Tags, ", "))
	}

	if len(r.Labels) > 0 {
		keys := make([]string, 0, len(r.Labels))
		for k := range r.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "Label:        %s=%s\n", k, r.Labels[k])
		}
	}

	if len(r.Issues) > 0 {
		fmt.Fprintln(w, "Issues:")
		for _, issue := range r.Issues {
			fmt.Fprintf(w, "  - %s\n", issue)
		}
	}
}
