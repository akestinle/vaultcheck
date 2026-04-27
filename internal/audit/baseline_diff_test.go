package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func makeBaseline(kvs map[string]string) *Baseline {
	secrets := make(map[string]Secret, len(kvs))
	for path, val := range kvs {
		secrets[path] = Secret{Path: path, Key: "key", Value: val, CreatedAt: time.Now()}
	}
	return &Baseline{CapturedAt: time.Now(), Secrets: secrets}
}

func TestDiffBaselines_NoChanges(t *testing.T) {
	old := makeBaseline(map[string]string{"secret/a": "v1"})
	cur := makeBaseline(map[string]string{"secret/a": "v1"})
	entries := DiffBaselines(old, cur)
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestDiffBaselines_Added(t *testing.T) {
	old := makeBaseline(map[string]string{})
	cur := makeBaseline(map[string]string{"secret/new": "v1"})
	entries := DiffBaselines(old, cur)
	if len(entries) != 1 || entries[0].Kind != BaselineAdded {
		t.Fatalf("expected 1 added entry, got %+v", entries)
	}
}

func TestDiffBaselines_Removed(t *testing.T) {
	old := makeBaseline(map[string]string{"secret/gone": "v1"})
	cur := makeBaseline(map[string]string{})
	entries := DiffBaselines(old, cur)
	if len(entries) != 1 || entries[0].Kind != BaselineRemoved {
		t.Fatalf("expected 1 removed entry, got %+v", entries)
	}
}

func TestDiffBaselines_Changed(t *testing.T) {
	old := makeBaseline(map[string]string{"secret/a": "v1"})
	cur := makeBaseline(map[string]string{"secret/a": "v2"})
	entries := DiffBaselines(old, cur)
	if len(entries) != 1 || entries[0].Kind != BaselineChanged {
		t.Fatalf("expected 1 changed entry, got %+v", entries)
	}
}

func TestWriteBaselineDiff_Empty(t *testing.T) {
	var buf bytes.Buffer
	WriteBaselineDiff(&buf, nil)
	if !strings.Contains(buf.String(), "No changes") {
		t.Fatalf("expected no-changes message, got %q", buf.String())
	}
}

func TestWriteBaselineDiff_Shows_Paths(t *testing.T) {
	old := makeBaseline(map[string]string{"secret/x": "old"})
	cur := makeBaseline(map[string]string{"secret/x": "new", "secret/y": "v1"})
	entries := DiffBaselines(old, cur)
	var buf bytes.Buffer
	WriteBaselineDiff(&buf, entries)
	out := buf.String()
	if !strings.Contains(out, "secret/x") || !strings.Contains(out, "secret/y") {
		t.Fatalf("expected both paths in output, got %q", out)
	}
}
