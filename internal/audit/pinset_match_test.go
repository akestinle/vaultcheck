package audit

import "testing"

func makePinsetSecrets() []Secret {
	return []Secret{
		{Path: "secret/alpha"},
		{Path: "secret/beta"},
		{Path: "secret/gamma"},
		{Path: "secret/delta"},
	}
}

func TestMatchPinset_AllMatched(t *testing.T) {
	ps := NewPinset()
	_ = ps.Add("all", []string{"secret/alpha", "secret/beta", "secret/gamma", "secret/delta"})
	res := MatchPinset(ps, "all", makePinsetSecrets())
	if len(res.Matched) != 4 {
		t.Fatalf("expected 4 matched, got %d", len(res.Matched))
	}
	if len(res.Unmatched) != 0 {
		t.Fatalf("expected 0 unmatched, got %d", len(res.Unmatched))
	}
}

func TestMatchPinset_Subset(t *testing.T) {
	ps := NewPinset()
	_ = ps.Add("subset", []string{"secret/alpha", "secret/gamma"})
	res := MatchPinset(ps, "subset", makePinsetSecrets())
	if len(res.Matched) != 2 {
		t.Fatalf("expected 2 matched, got %d", len(res.Matched))
	}
	if len(res.Unmatched) != 2 {
		t.Fatalf("expected 2 unmatched, got %d", len(res.Unmatched))
	}
}

func TestMatchPinset_NoneMatched(t *testing.T) {
	ps := NewPinset()
	_ = ps.Add("other", []string{"secret/zz"})
	res := MatchPinset(ps, "other", makePinsetSecrets())
	if len(res.Matched) != 0 {
		t.Fatalf("expected 0 matched, got %d", len(res.Matched))
	}
	if len(res.Unmatched) != 4 {
		t.Fatalf("expected 4 unmatched, got %d", len(res.Unmatched))
	}
}

func TestMatchPinset_UnknownPinset(t *testing.T) {
	ps := NewPinset()
	res := MatchPinset(ps, "missing", makePinsetSecrets())
	if len(res.Matched) != 0 {
		t.Fatal("expected 0 matched for unknown pinset")
	}
	if len(res.Unmatched) != 4 {
		t.Fatalf("expected all secrets unmatched, got %d", len(res.Unmatched))
	}
}

func TestFilterByPinset_ReturnsMatched(t *testing.T) {
	ps := NewPinset()
	_ = ps.Add("grp", []string{"secret/beta", "secret/delta"})
	result := FilterByPinset(ps, "grp", makePinsetSecrets())
	if len(result) != 2 {
		t.Fatalf("expected 2 filtered secrets, got %d", len(result))
	}
	if result[0].Path != "secret/beta" || result[1].Path != "secret/delta" {
		t.Errorf("unexpected paths: %v", result)
	}
}

func TestMatchPinset_ResultNameSet(t *testing.T) {
	ps := NewPinset()
	_ = ps.Add("mygroup", []string{"secret/alpha"})
	res := MatchPinset(ps, "mygroup", makePinsetSecrets())
	if res.Name != "mygroup" {
		t.Errorf("expected name %q, got %q", "mygroup", res.Name)
	}
}
