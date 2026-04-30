package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNewInspector_NotNil(t *testing.T) {
	ins := NewInspector(nil, nil, nil)
	if ins == nil {
		t.Fatal("expected non-nil Inspector")
	}
}

func TestInspect_BasicFields(t *testing.T) {
	ins := NewInspector(nil, nil, nil)
	s := Secret{
		Path:      "secret/db/password",
		Owner:     "team-db",
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	r := ins.Inspect(s)
	if r.Secret.Path != s.Path {
		t.Errorf("expected path %q, got %q", s.Path, r.Secret.Path)
	}
	if r.Agedays < 1 {
		t.Errorf("expected age >= 1, got %d", r.Agedays)
	}
	if r.InspectedAt.IsZero() {
		t.Error("expected non-zero InspectedAt")
	}
}

func TestInspect_ExpiredAddsIssue(t *testing.T) {
	ins := NewInspector(nil, nil, nil)
	past := time.Now().Add(-24 * time.Hour)
	s := Secret{
		Path:      "secret/old",
		ExpiresAt: &past,
		CreatedAt: time.Now().Add(-72 * time.Hour),
	}
	r := ins.Inspect(s)
	found := false
	for _, issue := range r.Issues {
		if strings.Contains(issue, "expired") {
			found = true
		}
	}
	if !found {
		t.Error("expected expired issue in result")
	}
}

func TestInspect_WithScorer_PopulatesRiskLevel(t *testing.T) {
	scorer := NewScorer()
	ins := NewInspector(scorer, nil, nil)
	s := Secret{
		Path:      "secret/app/token",
		CreatedAt: time.Now().Add(-400 * 24 * time.Hour),
	}
	r := ins.Inspect(s)
	if r.RiskLevel == "" {
		t.Error("expected non-empty RiskLevel from scorer")
	}
}

func TestWriteInspectResult_ContainsPath(t *testing.T) {
	ins := NewInspector(nil, nil, nil)
	s := Secret{
		Path:      "secret/svc/key",
		Owner:     "team-svc",
		CreatedAt: time.Now().Add(-10 * 24 * time.Hour),
	}
	r := ins.Inspect(s)
	var buf bytes.Buffer
	WriteInspectResult(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "secret/svc/key") {
		t.Errorf("expected path in output, got:\n%s", out)
	}
	if !strings.Contains(out, "team-svc") {
		t.Errorf("expected owner in output, got:\n%s", out)
	}
}

func TestWriteInspectResult_ShowsLabels(t *testing.T) {
	ins := NewInspector(nil, nil, nil)
	s := Secret{
		Path:      "secret/labeled",
		CreatedAt: time.Now(),
		Labels:    map[string]string{"env": "prod"},
	}
	r := ins.Inspect(s)
	r.Labels = s.Labels
	var buf bytes.Buffer
	WriteInspectResult(&buf, r)
	if !strings.Contains(buf.String(), "env=prod") {
		t.Errorf("expected label in output")
	}
}
