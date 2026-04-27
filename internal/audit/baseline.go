package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Baseline is an indexed snapshot of secrets at a point in time.
type Baseline struct {
	CapturedAt time.Time         `json:"captured_at"`
	Secrets    map[string]Secret `json:"secrets"`
}

// NewBaseline creates a Baseline from a slice of secrets, indexed by path.
func NewBaseline(secrets []Secret) *Baseline {
	idx := make(map[string]Secret, len(secrets))
	for _, s := range secrets {
		idx[s.Path] = s
	}
	return &Baseline{
		CapturedAt: time.Now(),
		Secrets:    idx,
	}
}

// SaveBaseline serialises a Baseline to a JSON file at path.
func SaveBaseline(b *Baseline, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating baseline file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		return fmt.Errorf("encoding baseline: %w", err)
	}
	return nil
}

// LoadBaseline reads and deserialises a Baseline from a JSON file at path.
func LoadBaseline(path string) (*Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("baseline file not found: %s", path)
		}
		return nil, fmt.Errorf("opening baseline file: %w", err)
	}
	defer f.Close()
	var b Baseline
	if err := json.NewDecoder(f).Decode(&b); err != nil {
		return nil, fmt.Errorf("decoding baseline: %w", err)
	}
	return &b, nil
}
