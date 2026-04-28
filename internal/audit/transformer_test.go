package audit

import (
	"testing"
	"time"
)

func transformerSecrets() []Secret {
	return []Secret{
		{Path: "  /Secret/DB  ", Key: "password", Value: "s3cr3t", Owner: "", CreatedAt: time.Now()},
		{Path: "OPS/API/KEY", Key: "token", Value: "abc123", Owner: "ops-team", CreatedAt: time.Now()},
	}
}

func TestNewTransformer_NotNil(t *testing.T) {
	tr := NewTransformer()
	if tr == nil {
		t.Fatal("expected non-nil Transformer")
	}
}

func TestTransformer_Add_NilIgnored(t *testing.T) {
	tr := NewTransformer()
	tr.Add(nil)
	if len(tr.funcs) != 0 {
		t.Fatalf("expected 0 funcs, got %d", len(tr.funcs))
	}
}

func TestTransformer_Transform_Empty(t *testing.T) {
	tr := NewTransformer()
	out := tr.Transform([]Secret{})
	if len(out) != 0 {
		t.Fatalf("expected empty slice, got %d", len(out))
	}
}

func TestNormalizePathTransform(t *testing.T) {
	tr := NewTransformer()
	tr.Add(NormalizePathTransform())

	secrets := transformerSecrets()
	out := tr.Transform(secrets)

	if out[0].Path != "secret/db" {
		t.Errorf("expected 'secret/db', got %q", out[0].Path)
	}
	if out[1].Path != "ops/api/key" {
		t.Errorf("expected 'ops/api/key', got %q", out[1].Path)
	}
}

func TestSetOwnerTransform_SetsWhenEmpty(t *testing.T) {
	tr := NewTransformer()
	tr.Add(SetOwnerTransform("default-team"))

	out := tr.Transform(transformerSecrets())

	if out[0].Owner != "default-team" {
		t.Errorf("expected 'default-team', got %q", out[0].Owner)
	}
	// pre-existing owner must be preserved
	if out[1].Owner != "ops-team" {
		t.Errorf("expected 'ops-team', got %q", out[1].Owner)
	}
}

func TestRedactValueTransform_Default(t *testing.T) {
	tr := NewTransformer()
	tr.Add(RedactValueTransform(""))

	out := tr.Transform(transformerSecrets())
	for _, s := range out {
		if s.Value != "***REDACTED***" {
			t.Errorf("expected redacted value, got %q", s.Value)
		}
	}
}

func TestRedactValueTransform_CustomPlaceholder(t *testing.T) {
	tr := NewTransformer()
	tr.Add(RedactValueTransform("[hidden]"))

	out := tr.Transform(transformerSecrets())
	if out[0].Value != "[hidden]" {
		t.Errorf("expected '[hidden]', got %q", out[0].Value)
	}
}

func TestTransformer_Pipeline_Order(t *testing.T) {
	tr := NewTransformer()
	tr.Add(NormalizePathTransform())
	tr.Add(SetOwnerTransform("fallback"))
	tr.Add(RedactValueTransform("X"))

	out := tr.Transform(transformerSecrets())

	if out[0].Path != "secret/db" {
		t.Errorf("path not normalized: %q", out[0].Path)
	}
	if out[0].Owner != "fallback" {
		t.Errorf("owner not set: %q", out[0].Owner)
	}
	if out[0].Value != "X" {
		t.Errorf("value not redacted: %q", out[0].Value)
	}
}
