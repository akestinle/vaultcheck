package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FrozenSecret represents a secret that has been frozen (locked from rotation).
type FrozenSecret struct {
	Path      string    `json:"path"`
	FrozenAt  time.Time `json:"frozen_at"`
	Reason    string    `json:"reason"`
	FrozenBy  string    `json:"frozen_by"`
}

// Freezer manages a set of frozen secret paths.
type Freezer struct {
	dir     string
	frozen  map[string]FrozenSecret
}

// NewFreezer creates a Freezer backed by the given directory.
func NewFreezer(dir string) (*Freezer, error) {
	if dir == "" {
		return nil, fmt.Errorf("freezer: directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("freezer: create dir: %w", err)
	}
	f := &Freezer{dir: dir, frozen: make(map[string]FrozenSecret)}
	_ = f.load() // best-effort load of existing state
	return f, nil
}

// Freeze marks a secret path as frozen.
func (f *Freezer) Freeze(path, reason, frozenBy string) error {
	if path == "" {
		return nil
	}
	f.frozen[path] = FrozenSecret{
		Path:     path,
		FrozenAt: time.Now().UTC(),
		Reason:   reason,
		FrozenBy: frozenBy,
	}
	return f.save()
}

// Unfreeze removes the freeze on a secret path.
func (f *Freezer) Unfreeze(path string) error {
	if _, ok := f.frozen[path]; !ok {
		return nil
	}
	delete(f.frozen, path)
	return f.save()
}

// IsFrozen reports whether the given path is currently frozen.
func (f *Freezer) IsFrozen(path string) bool {
	_, ok := f.frozen[path]
	return ok
}

// Entries returns all frozen secrets.
func (f *Freezer) Entries() []FrozenSecret {
	out := make([]FrozenSecret, 0, len(f.frozen))
	for _, v := range f.frozen {
		out = append(out, v)
	}
	return out
}

func (f *Freezer) filePath() string {
	return filepath.Join(f.dir, "freezer.json")
}

func (f *Freezer) save() error {
	data, err := json.MarshalIndent(f.frozen, "", "  ")
	if err != nil {
		return fmt.Errorf("freezer: marshal: %w", err)
	}
	return os.WriteFile(f.filePath(), data, 0o600)
}

func (f *Freezer) load() error {
	data, err := os.ReadFile(f.filePath())
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &f.frozen)
}
