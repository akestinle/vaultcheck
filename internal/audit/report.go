package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"
)

// Report summarises the result of an audit scan.
type Report struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Mount       string       `json:"mount"`
	TotalPaths  int          `json:"total_paths"`
	Secrets     []SecretMeta `json:"secrets"`
}

// NewReport builds a Report from scan results.
func NewReport(mount string, secrets []SecretMeta) Report {
	return Report{
		GeneratedAt: time.Now().UTC(),
		Mount:       mount,
		TotalPaths:  len(secrets),
		Secrets:     secrets,
	}
}

// WriteJSON serialises the report as indented JSON to w.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteTable writes a human-readable table of secrets to w.
func (r Report) WriteTable(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "PATH\tVERSION\tKEY COUNT\n")
	fmt.Fprintf(tw, "----\t-------\t---------\n")
	for _, s := range r.Secrets {
		fmt.Fprintf(tw, "%s\t%d\t%d\n", s.Path, s.Version, len(s.Keys))
	}
	return tw.Flush()
}
