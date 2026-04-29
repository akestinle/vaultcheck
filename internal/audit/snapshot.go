package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Snapshot captures a point-in-time view of scanned secrets with metadata.
type Snapshot struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Label     string    `json:"label,omitempty"`
	Secrets   []Secret  `json:"secrets"`
	Count     int       `json:"count"`
}

// NewSnapshot creates a Snapshot from a slice of secrets.
func NewSnapshot(secrets []Secret, label string) *Snapshot {
	now := time.Now().UTC()
	return &Snapshot{
		ID:        fmt.Sprintf("%d", now.UnixNano()),
		CreatedAt: now,
		Label:     label,
		Secrets:   secrets,
		Count:     len(secrets),
	}
}

// SaveSnapshot writes a snapshot to dir as a JSON file named by its ID.
func SaveSnapshot(dir string, snap *Snapshot) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("snapshot: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, snap.ID+".json")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("snapshot: create %s: %w", path, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}

// LoadSnapshot reads a snapshot from a JSON file at path.
func LoadSnapshot(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("snapshot: open %s: %w", path, err)
	}
	defer f.Close()
	var snap Snapshot
	if err := json.NewDecoder(f).Decode(&snap); err != nil {
		return nil, fmt.Errorf("snapshot: decode %s: %w", path, err)
	}
	return &snap, nil
}
