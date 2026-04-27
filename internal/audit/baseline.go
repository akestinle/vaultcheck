package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Baseline represents a saved snapshot of secrets at a point in time.
type Baseline struct {
	CapturedAt time.Time         `json:"captured_at"`
	Secrets    map[string]Secret `json:"secrets"`
}

// NewBaseline creates a Baseline from a slice of secrets.
func NewBaseline(secrets []Secret) *Baseline {
	m := make(map[string]Secret, len(secrets))
	for _, s := range secrets {
		m[s.Path] = s
	}
	return &Baseline{
		CapturedAt: time.Now().UTC(),
		Secrets:    m,
	}
}

// SaveBaseline writes a Baseline to a JSON file at the given path.
func SaveBaseline(b *Baseline, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("baseline: create file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

// LoadBaseline reads a Baseline from a JSON file at the given path.
func LoadBaseline(path string) (*Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: open file: %w", err)
	}
	defer f.Close()
	var b Baseline
	if err := json.NewDecoder(f).Decode(&b); err != nil {
		return nil, fmt.Errorf("baseline: decode: %w", err)
	}
	return &b, nil
}
