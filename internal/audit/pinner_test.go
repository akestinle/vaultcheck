package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNewPinner_NotNil(t *testing.T) {
	p := NewPinner()
	if p == nil {
		t.Fatal("expected non-nil Pinner")
	}
}

func TestPin_EmptyPathIgnored(t *testing.T) {
	p := NewPinner()
	p.Pin("", "abc123", "user")
	if p.IsPinned("") {
		t.Error("empty path should not be pinned")
	}
}

func TestPin_EmptyHashIgnored(t *testing.T) {
	p := NewPinner()
	p.Pin("secret/a", "", "user")
	if p.IsPinned("secret/a") {
		t.Error("empty hash should not create a pin")
	}
}

func TestIsPinned_AfterPin(t *testing.T) {
	p := NewPinner()
	p.Pin("secret/a", "hash1", "alice")
	if !p.IsPinned("secret/a") {
		t.Error("expected secret/a to be pinned")
	}
}

func TestUnpin_RemovesPin(t *testing.T) {
	p := NewPinner()
	p.Pin("secret/a", "hash1", "alice")
	p.Unpin("secret/a")
	if p.IsPinned("secret/a") {
		t.Error("expected secret/a to be unpinned")
	}
}

func TestPinDrift_NoDrift(t *testing.T) {
	p := NewPinner()
	p.Pin("secret/a", "hash1", "alice")
	secrets := []Secret{{Path: "secret/a", ValueHash: "hash1"}}
	drifted := p.PinDrift(secrets)
	if len(drifted) != 0 {
		t.Errorf("expected no drift, got %v", drifted)
	}
}

func TestPinDrift_DetectsDrift(t *testing.T) {
	p := NewPinner()
	p.Pin("secret/a", "hash1", "alice")
	p.Pin("secret/b", "hash2", "bob")
	secrets := []Secret{
		{Path: "secret/a", ValueHash: "hash-changed"},
		{Path: "secret/b", ValueHash: "hash2"},
	}
	drifted := p.PinDrift(secrets)
	if len(drifted) != 1 || drifted[0] != "secret/a" {
		t.Errorf("expected [secret/a] drifted, got %v", drifted)
	}
}

func TestPinDrift_UnpinnedSecretIgnored(t *testing.T) {
	p := NewPinner()
	secrets := []Secret{{Path: "secret/x", ValueHash: "anything"}}
	drifted := p.PinDrift(secrets)
	if len(drifted) != 0 {
		t.Errorf("expected no drift for unpinned secret, got %v", drifted)
	}
}

func TestWritePinReport_NoDrift(t *testing.T) {
	p := NewPinner()
	var buf bytes.Buffer
	p.WritePinReport(&buf, nil)
	if !strings.Contains(buf.String(), "no drift") {
		t.Errorf("expected 'no drift' message, got: %s", buf.String())
	}
}

func TestWritePinReport_WithDrift(t *testing.T) {
	p := NewPinner()
	p.pins["secret/a"] = PinEntry{
		Path:      "secret/a",
		ValueHash: "old",
		PinnedAt:  time.Now().UTC(),
		PinnedBy:  "ci",
	}
	var buf bytes.Buffer
	p.WritePinReport(&buf, []string{"secret/a"})
	out := buf.String()
	if !strings.Contains(out, "DRIFTED") {
		t.Errorf("expected DRIFTED in output, got: %s", out)
	}
	if !strings.Contains(out, "secret/a") {
		t.Errorf("expected path in output, got: %s", out)
	}
}
