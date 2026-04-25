package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func summarySecrets() []Secret {
	now := time.Now().UTC()
	past := now.Add(-60 * 24 * time.Hour)
	soon := now.Add(10 * 24 * time.Hour)
	old := now.Add(-365 * 24 * time.Hour)

	return []Secret{
		{Path: "secret/app/db", UpdatedAt: old, ExpiresAt: &past},   // expired
		{Path: "secret/app/api", UpdatedAt: now, ExpiresAt: &soon},  // expiring soon
		{Path: "secret/infra/tls", UpdatedAt: now, ExpiresAt: nil},  // no expiry
		{Path: "secret/infra/ssh", UpdatedAt: past, ExpiresAt: nil}, // older
	}
}

func TestNewSummary_TotalCount(t *testing.T) {
	s := NewSummary(summarySecrets())
	if s.TotalSecrets != 4 {
		t.Fatalf("expected 4 total secrets, got %d", s.TotalSecrets)
	}
}

func TestNewSummary_ExpiredCount(t *testing.T) {
	s := NewSummary(summarySecrets())
	if s.ExpiredSecrets != 1 {
		t.Fatalf("expected 1 expired secret, got %d", s.ExpiredSecrets)
	}
}

func TestNewSummary_ExpiringIn30(t *testing.T) {
	s := NewSummary(summarySecrets())
	if s.ExpiringIn30 != 1 {
		t.Fatalf("expected 1 secret expiring in 30 days, got %d", s.ExpiringIn30)
	}
}

func TestNewSummary_OldestNewest(t *testing.T) {
	s := NewSummary(summarySecrets())
	if s.OldestSecret == nil || s.OldestSecret.Path != "secret/app/db" {
		t.Fatalf("unexpected oldest secret: %v", s.OldestSecret)
	}
	if s.NewestSecret == nil {
		t.Fatal("expected a newest secret")
	}
}

func TestNewSummary_PathCounts(t *testing.T) {
	s := NewSummary(summarySecrets())
	if s.PathCounts["secret"] != 4 {
		t.Fatalf("expected 4 under 'secret', got %d", s.PathCounts["secret"])
	}
}

func TestNewSummary_Empty(t *testing.T) {
	s := NewSummary([]Secret{})
	if s.TotalSecrets != 0 || s.OldestSecret != nil || s.NewestSecret != nil {
		t.Fatal("expected zero-value summary for empty input")
	}
}

func TestSummary_WriteSummary_ContainsFields(t *testing.T) {
	s := NewSummary(summarySecrets())
	var buf bytes.Buffer
	if err := s.WriteSummary(&buf); err != nil {
		t.Fatalf("WriteSummary error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Total secrets", "Expired", "Expiring", "secret/app/db"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

func TestTopLevelSegment(t *testing.T) {
	cases := []struct{ path, want string }{
		{"secret/app/key", "secret"},
		{"nosegment", "nosegment"},
		{"a/b", "a"},
	}
	for _, c := range cases {
		if got := topLevelSegment(c.path); got != c.want {
			t.Errorf("topLevelSegment(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
