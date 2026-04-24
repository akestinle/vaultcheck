package rotation_test

import (
	"encoding/base64"
	"testing"

	"github.com/user/vaultcheck/internal/rotation"
)

func TestNewRandomGenerator_TooShort(t *testing.T) {
	_, err := rotation.NewRandomGenerator(8)
	if err == nil {
		t.Fatal("expected error for byteLength < 16")
	}
}

func TestNewRandomGenerator_Valid(t *testing.T) {
	gen, err := rotation.NewRandomGenerator(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gen == nil {
		t.Fatal("expected non-nil generator")
	}
}

func TestRandomGenerator_Generate_Length(t *testing.T) {
	gen, _ := rotation.NewRandomGenerator(32)
	data, err := gen.Generate("secret/data/test")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	v, ok := data["value"].(string)
	if !ok {
		t.Fatal("expected string value")
	}
	decoded, err := base64.URLEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(decoded))
	}
}

func TestRandomGenerator_Generate_Unique(t *testing.T) {
	gen, _ := rotation.NewRandomGenerator(32)
	a, _ := gen.Generate("secret/data/x")
	b, _ := gen.Generate("secret/data/x")
	if a["value"] == b["value"] {
		t.Error("two successive Generate calls returned identical values")
	}
}
