package policy

import (
	"bytes"
	"strings"
	"testing"
)

func TestDiff_NoChanges(t *testing.T) {
	base := PolicyMap{"admin": `path "secret/*" { capabilities = ["read"] }`}
	curr := PolicyMap{"admin": `path "secret/*" { capabilities = ["read"] }`}

	result := Diff(base, curr)
	if !result.IsEmpty() {
		t.Errorf("expected empty diff, got %+v", result)
	}
}

func TestDiff_Added(t *testing.T) {
	base := PolicyMap{}
	curr := PolicyMap{"reader": `path "secret/*" { capabilities = ["read"] }`}

	result := Diff(base, curr)
	if len(result.Added) != 1 || result.Added[0] != "reader" {
		t.Errorf("expected Added=[reader], got %v", result.Added)
	}
	if len(result.Removed) != 0 || len(result.Changed) != 0 {
		t.Errorf("unexpected removed/changed: %+v", result)
	}
}

func TestDiff_Removed(t *testing.T) {
	base := PolicyMap{"old": `path "kv/*" { capabilities = ["delete"] }`}
	curr := PolicyMap{}

	result := Diff(base, curr)
	if len(result.Removed) != 1 || result.Removed[0] != "old" {
		t.Errorf("expected Removed=[old], got %v", result.Removed)
	}
}

func TestDiff_Changed(t *testing.T) {
	base := PolicyMap{"writer": `path "secret/*" { capabilities = ["read"] }`}
	curr := PolicyMap{"writer": `path "secret/*" { capabilities = ["read", "write"] }`}

	result := Diff(base, curr)
	if len(result.Changed) != 1 {
		t.Fatalf("expected 1 changed policy, got %d", len(result.Changed))
	}
	if result.Changed[0].Name != "writer" {
		t.Errorf("expected changed policy 'writer', got %s", result.Changed[0].Name)
	}
}

func TestDiff_Mixed(t *testing.T) {
	base := PolicyMap{
		"keep":   `path "a" {}`,
		"remove": `path "b" {}`,
		"change": `path "c" { capabilities = ["read"] }`,
	}
	curr := PolicyMap{
		"keep":   `path "a" {}`,
		"add":    `path "d" {}`,
		"change": `path "c" { capabilities = ["read", "list"] }`,
	}

	result := Diff(base, curr)
	if len(result.Added) != 1 || result.Added[0] != "add" {
		t.Errorf("Added mismatch: %v", result.Added)
	}
	if len(result.Removed) != 1 || result.Removed[0] != "remove" {
		t.Errorf("Removed mismatch: %v", result.Removed)
	}
	if len(result.Changed) != 1 || result.Changed[0].Name != "change" {
		t.Errorf("Changed mismatch: %v", result.Changed)
	}
}

func TestWriteDiff_Empty(t *testing.T) {
	var buf bytes.Buffer
	WriteDiff(&buf, &DiffResult{})
	if !strings.Contains(buf.String(), "No policy changes") {
		t.Errorf("expected no-change message, got: %s", buf.String())
	}
}

func TestWriteDiff_Output(t *testing.T) {
	d := &DiffResult{
		Added:   []string{"newpol"},
		Removed: []string{"oldpol"},
		Changed: []PolicyChange{{Name: "mod", OldHCL: "old", NewHCL: "new"}},
	}
	var buf bytes.Buffer
	WriteDiff(&buf, d)
	out := buf.String()
	for _, want := range []string{"[+] ADDED   newpol", "[-] REMOVED oldpol", "[~] CHANGED mod"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, out)
		}
	}
}
