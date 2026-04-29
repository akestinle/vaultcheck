package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func makeSnap(secrets []Secret, label string) *Snapshot {
	return NewSnapshot(secrets, label)
}

func TestDiffSnapshots_NoChanges(t *testing.T) {
	secrets := []Secret{
		{Path: "secret/a", Key: "k", Value: "v1", CreatedAt: time.Now()},
	}
	before := makeSnap(secrets, "before")
	after := makeSnap(secrets, "after")
	result := DiffSnapshots(before, after)
	if len(result.Added)+len(result.Removed)+len(result.Changed) != 0 {
		t.Errorf("expected no changes, got added=%d removed=%d changed=%d",
			len(result.Added), len(result.Removed), len(result.Changed))
	}
}

func TestDiffSnapshots_Added(t *testing.T) {
	before := makeSnap([]Secret{}, "before")
	after := makeSnap([]Secret{{Path: "secret/new", Key: "k", Value: "v", CreatedAt: time.Now()}}, "after")
	result := DiffSnapshots(before, after)
	if len(result.Added) != 1 {
		t.Errorf("expected 1 added, got %d", len(result.Added))
	}
}

func TestDiffSnapshots_Removed(t *testing.T) {
	before := makeSnap([]Secret{{Path: "secret/old", Key: "k", Value: "v", CreatedAt: time.Now()}}, "before")
	after := makeSnap([]Secret{}, "after")
	result := DiffSnapshots(before, after)
	if len(result.Removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(result.Removed))
	}
}

func TestDiffSnapshots_Changed(t *testing.T) {
	now := time.Now()
	before := makeSnap([]Secret{{Path: "secret/x", Key: "k", Value: "old", CreatedAt: now}}, "before")
	after := makeSnap([]Secret{{Path: "secret/x", Key: "k", Value: "new", CreatedAt: now}}, "after")
	result := DiffSnapshots(before, after)
	if len(result.Changed) != 1 {
		t.Errorf("expected 1 changed, got %d", len(result.Changed))
	}
}

func TestWriteSnapshotDiff_Output(t *testing.T) {
	now := time.Now()
	before := makeSnap([]Secret{{Path: "secret/a", Key: "k", Value: "v1", CreatedAt: now}}, "before")
	after := makeSnap([]Secret{
		{Path: "secret/a", Key: "k", Value: "v2", CreatedAt: now},
		{Path: "secret/b", Key: "k", Value: "vb", CreatedAt: now},
	}, "after")
	result := DiffSnapshots(before, after)
	var buf bytes.Buffer
	WriteSnapshotDiff(&buf, before, after, result)
	out := buf.String()
	if !strings.Contains(out, "Added:") {
		t.Error("expected 'Added:' in output")
	}
	if !strings.Contains(out, "Changed:") {
		t.Error("expected 'Changed:' in output")
	}
}
