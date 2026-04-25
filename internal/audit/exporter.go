package audit

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Exporter writes audit report data to various output formats.
type Exporter struct {
	report *Report
}

// NewExporter creates an Exporter from the given Report.
func NewExporter(r *Report) (*Exporter, error) {
	if r == nil {
		return nil, fmt.Errorf("report must not be nil")
	}
	return &Exporter{report: r}, nil
}

// WriteCSV writes the report secrets as CSV rows to w.
// Columns: path, key, age_days, expires_at.
func (e *Exporter) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"path", "key", "age_days", "expires_at"}); err != nil {
		return fmt.Errorf("writing csv header: %w", err)
	}
	for _, s := range e.report.Secrets {
		ageDays := strconv.Itoa(int(time.Since(s.CreatedAt).Hours() / 24))
		expiresAt := ""
		if !s.ExpiresAt.IsZero() {
			expiresAt = s.ExpiresAt.Format(time.RFC3339)
		}
		if err := cw.Write([]string{s.Path, s.Key, ageDays, expiresAt}); err != nil {
			return fmt.Errorf("writing csv row: %w", err)
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteSummary writes a human-readable summary line to w.
func (e *Exporter) WriteSummary(w io.Writer) error {
	_, err := fmt.Fprintf(w,
		"Audit Report — Generated: %s | Secrets: %d | Scanned: %d\n",
		e.report.GeneratedAt.Format(time.RFC3339),
		len(e.report.Secrets),
		e.report.ScannedPaths,
	)
	return err
}
