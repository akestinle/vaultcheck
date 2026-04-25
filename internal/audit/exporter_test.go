package audit

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func TestNewExporter_NilReport(t *testing.T) {
	_, err := NewExporter(nil)
	if err == nil {
		t.Fatal("expected error for nil report")
	}
}

func TestNewExporter_Valid(t *testing.T) {
	r := sampleReport()
	e, err := NewExporter(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil exporter")
	}
}

func TestExporter_WriteCSV_Headers(t *testing.T) {
	e, _ := NewExporter(sampleReport())
	var buf bytes.Buffer
	if err := e.WriteCSV(&buf); err != nil {
		t.Fatalf("WriteCSV error: %v", err)
	}
	r := csv.NewReader(&buf)
	header, err := r.Read()
	if err != nil {
		t.Fatalf("reading header: %v", err)
	}
	want := []string{"path", "key", "age_days", "expires_at"}
	for i, h := range want {
		if header[i] != h {
			t.Errorf("header[%d] = %q, want %q", i, header[i], h)
		}
	}
}

func TestExporter_WriteCSV_Rows(t *testing.T) {
	e, _ := NewExporter(sampleReport())
	var buf bytes.Buffer
	if err := e.WriteCSV(&buf); err != nil {
		t.Fatalf("WriteCSV error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// header + 2 data rows from sampleReport
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
}

func TestExporter_WriteSummary(t *testing.T) {
	e, _ := NewExporter(sampleReport())
	var buf bytes.Buffer
	if err := e.WriteSummary(&buf); err != nil {
		t.Fatalf("WriteSummary error: %v", err)
	}
	if !strings.Contains(buf.String(), "Audit Report") {
		t.Errorf("summary missing 'Audit Report' prefix: %q", buf.String())
	}
}

// sampleReport builds a minimal Report for exporter tests.
func sampleReport() *Report {
	now := time.Now()
	secrets := []Secret{
		{Path: "secret/a", Key: "api_key", CreatedAt: now.Add(-48 * time.Hour)},
		{Path: "secret/b", Key: "db_pass", CreatedAt: now.Add(-10 * time.Hour), ExpiresAt: now.Add(24 * time.Hour)},
	}
	return &Report{
		GeneratedAt:  now,
		ScannedPaths: 2,
		Secrets:      secrets,
	}
}
