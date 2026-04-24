package rotation

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// RandomGenerator creates cryptographically random base64-encoded secrets.
type RandomGenerator struct {
	// ByteLength controls how many random bytes are generated.
	ByteLength int
}

// NewRandomGenerator returns a RandomGenerator with sensible defaults.
func NewRandomGenerator(byteLength int) (*RandomGenerator, error) {
	if byteLength < 16 {
		return nil, fmt.Errorf("byteLength must be at least 16, got %d", byteLength)
	}
	return &RandomGenerator{ByteLength: byteLength}, nil
}

// Generate returns a map with a single "value" key containing a random secret.
// The secret is base64 URL-encoded, making it safe for use in URLs and HTTP headers.
func (g *RandomGenerator) Generate(_ string) (map[string]interface{}, error) {
	buf := make([]byte, g.ByteLength)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	return map[string]interface{}{
		"value": base64.URLEncoding.EncodeToString(buf),
	}, nil
}

// GenerateRaw returns a raw random byte slice of the configured length.
// This is useful when callers need the bytes directly rather than a map.
func (g *RandomGenerator) GenerateRaw() ([]byte, error) {
	buf := make([]byte, g.ByteLength)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	return buf, nil
}
