package rotation

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
)

// Result holds the outcome of a single secret rotation.
type Result struct {
	Path      string
	RotatedAt time.Time
	Success   bool
	Error     error
}

// Rotator rotates secrets stored in Vault.
type Rotator struct {
	client    *api.Client
	generator Generator
}

// Generator produces a new secret value for a given path.
type Generator interface {
	Generate(path string) (map[string]interface{}, error)
}

// NewRotator constructs a Rotator with the provided Vault client and generator.
func NewRotator(client *api.Client, gen Generator) (*Rotator, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client must not be nil")
	}
	if gen == nil {
		return nil, fmt.Errorf("generator must not be nil")
	}
	return &Rotator{client: client, generator: gen}, nil
}

// Rotate iterates over the given paths and writes new secret values.
func (r *Rotator) Rotate(ctx context.Context, paths []string) []Result {
	results := make([]Result, 0, len(paths))
	for _, p := range paths {
		res := Result{Path: p, RotatedAt: time.Now().UTC()}
		data, err := r.generator.Generate(p)
		if err != nil {
			res.Error = fmt.Errorf("generate: %w", err)
			results = append(results, res)
			continue
		}
		_, err = r.client.Logical().WriteWithContext(ctx, p, data)
		if err != nil {
			res.Error = fmt.Errorf("write: %w", err)
		} else {
			res.Success = true
		}
		results = append(results, res)
	}
	return results
}
