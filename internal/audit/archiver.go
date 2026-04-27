package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ArchiveEntry holds a timestamped snapshot of secrets.
type ArchiveEntry struct {
	ArchivedAt time.Time `json:"archived_at"`
	Secrets    []Secret  `json:"secrets"`
}

// Archiver persists audit snapshots to a directory on disk.
type Archiver struct {
	dir string
}

// NewArchiver creates an Archiver that stores snapshots in dir.
// Returns an error if dir cannot be created.
func NewArchiver(dir string) (*Archiver, error) {
	if dir == "" {
		return nil, fmt.Errorf("archiver: directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("archiver: failed to create directory: %w", err)
	}
	return &Archiver{dir: dir}, nil
}

// Archive writes secrets as a JSON snapshot file named by the current UTC time.
func (a *Archiver) Archive(secrets []Secret) (string, error) {
	entry := ArchiveEntry{
		ArchivedAt: time.Now().UTC(),
		Secrets:    secrets,
	}
	filename := entry.ArchivedAt.Format("20060102T150405Z") + ".json"
	path := filepath.Join(a.dir, filename)

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("archiver: failed to create file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entry); err != nil {
		return "", fmt.Errorf("archiver: failed to encode snapshot: %w", err)
	}
	return path, nil
}

// LoadArchive reads a previously saved archive entry from path.
func LoadArchive(path string) (*ArchiveEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("archiver: failed to open file: %w", err)
	}
	defer f.Close()

	var entry ArchiveEntry
	if err := json.NewDecoder(f).Decode(&entry); err != nil {
		return nil, fmt.Errorf("archiver: failed to decode snapshot: %w", err)
	}
	return &entry, nil
}
