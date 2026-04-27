package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func makeSecret(path, value string) Secret {
	return Secret{Path: path, Value: value, CreatedAt: time.Now()}
}

func TestCompare_NoChanges(t *testing.T) {
	before := []Secret{makeSecret("a", "v1"), makeSecret("b", "v2")}
	after := []Secret{makeSecret("a", "v1"), makeSecret("b", "v2")}
	r := Compare(before, after)
	if r.HasChanges() {
		t.Fatal("expected no changes")
	}
	if len(r.Unchanged) != 2 {
		t.Fatalf("expected 2 unchanged, got %d", len(r.Unchanged))
	}
}

func TestCompare_Added(t *testing.T) {
	before := []Secret{makeSecret("a", "v1")}
	after := []Secret{makeSecret("a", "v1"), makeSecret("b", "v2")}
	r := Compare(before, after)
	if len(r.Added) != 1 || r.Added[0].Path != "b" {
		t.Fatalf("expected 1 added secret 'b', got %+v", r.Added)
	}
}

func TestCompare_Removed(t *testing.T) {
	before := []Secret{makeSecret("a", "v1"), makeSecret("b", "v2")}
	after := []Secret{makeSecret("a", "v1")}
	r := Compare(before, after)
	if len(r.Removed) != 1 || r.Removed[0].Path != "b" {
		t.Fatalf("expected 1 removed secret 'b', got %+v", r.Removed)
	}
}

func TestCompare_Changed(t *testing.T) {
	before := []Secret{makeSecret("a", "old")}
	after := []Secret{makeSecret("a", "new")}
	r := Compare(before, after)
	if len(r.Changed) != 1 || r.Changed[0].Path != "a" {
		t.Fatalf("expected 1 changed secret 'a', got %+v", r.Changed)
	}
}

func TestCompare_TotalDelta(t *testing.T) {
	before := []Secret{makeSecret("a", "v1")}
	after := []Secret{makeSecret("b", "v2"), makeSecret("c", "v3")}
	r := Compare(before, after)
	if r.TotalDelta() != 1 {
		t.Fatalf("expected delta 1 (2 added - 1 removed), got %d", r.TotalDelta())
	}
}

func TestWriteCompareResult_NoChanges(t *testing.T) {
	r := &CompareResult{}
	var buf bytes.Buffer
	if err := WriteCompareResult(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no changes") {
		t.Fatalf("expected 'no changes' in output, got: %s", buf.String())
	}
}

func TestWriteCompareResult_ShowsAllStatuses(t *testing.T) {
	r := &CompareResult{
		Added:   []Secret{makeSecret("new/secret", "x")},
		Removed: []Secret{makeSecret("old/secret", "y")},
		Changed: []Secret{makeSecret("mod/secret", "z")},
	}
	var buf bytes.Buffer
	if err := WriteCompareResult(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"added", "removed", "changed", "new/secret", "old/secret", "mod/secret"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}
