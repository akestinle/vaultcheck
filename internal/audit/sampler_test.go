package audit

import (
	"testing"
)

var samplerSecrets = []Secret{
	{Path: "secret/alpha", Value: "a"},
	{Path: "secret/beta", Value: "b"},
	{Path: "secret/gamma", Value: "c"},
	{Path: "secret/delta", Value: "d"},
	{Path: "secret/epsilon", Value: "e"},
}

func TestNewSampler_NotNil(t *testing.T) {
	s := NewSampler(DefaultSampleOptions())
	if s == nil {
		t.Fatal("expected non-nil Sampler")
	}
}

func TestNewSampler_ClampsNToOne(t *testing.T) {
	s := NewSampler(SampleOptions{N: 0, Mode: SampleFirst})
	result := s.Sample(samplerSecrets)
	if len(result) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(result))
	}
}

func TestSampler_Sample_Empty(t *testing.T) {
	s := NewSampler(DefaultSampleOptions())
	result := s.Sample(nil)
	if len(result) != 0 {
		t.Fatalf("expected empty result, got %d", len(result))
	}
}

func TestSampler_Sample_NGreaterThanPool(t *testing.T) {
	s := NewSampler(SampleOptions{N: 100, Mode: SampleFirst})
	result := s.Sample(samplerSecrets)
	if len(result) != len(samplerSecrets) {
		t.Fatalf("expected %d secrets, got %d", len(samplerSecrets), len(result))
	}
}

func TestSampler_Sample_First(t *testing.T) {
	s := NewSampler(SampleOptions{N: 2, Mode: SampleFirst})
	result := s.Sample(samplerSecrets)
	if len(result) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(result))
	}
	if result[0].Path != "secret/alpha" || result[1].Path != "secret/beta" {
		t.Errorf("unexpected first paths: %v, %v", result[0].Path, result[1].Path)
	}
}

func TestSampler_Sample_Last(t *testing.T) {
	s := NewSampler(SampleOptions{N: 2, Mode: SampleLast})
	result := s.Sample(samplerSecrets)
	if len(result) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(result))
	}
	if result[0].Path != "secret/gamma" || result[1].Path != "secret/epsilon" {
		t.Errorf("unexpected last paths: %v, %v", result[0].Path, result[1].Path)
	}
}

func TestSampler_Sample_Random_Deterministic(t *testing.T) {
	opts := SampleOptions{N: 3, Mode: SampleRandom, Seed: 99}
	s1 := NewSampler(opts)
	s2 := NewSampler(opts)
	r1 := s1.Sample(samplerSecrets)
	r2 := s2.Sample(samplerSecrets)
	if len(r1) != 3 || len(r2) != 3 {
		t.Fatalf("expected 3 secrets each")
	}
	for i := range r1 {
		if r1[i].Path != r2[i].Path {
			t.Errorf("non-deterministic at index %d: %v != %v", i, r1[i].Path, r2[i].Path)
		}
	}
}

func TestSampler_DoesNotMutateInput(t *testing.T) {
	original := make([]Secret, len(samplerSecrets))
	copy(original, samplerSecrets)
	s := NewSampler(SampleOptions{N: 3, Mode: SampleRandom, Seed: 7})
	s.Sample(samplerSecrets)
	for i, sec := range samplerSecrets {
		if sec.Path != original[i].Path {
			t.Errorf("input mutated at index %d", i)
		}
	}
}
