package audit

import (
	"fmt"
	"strings"
)

// ValidationRule defines a single validation check for a secret.
type ValidationRule struct {
	Name    string
	Check   func(s Secret) error
}

// ValidationResult holds the outcome of validating a single secret.
type ValidationResult struct {
	Secret  Secret
	Errors  []string
}

// IsValid returns true if no errors were found.
func (r ValidationResult) IsValid() bool {
	return len(r.Errors) == 0
}

// Validator applies a set of rules to a slice of secrets.
type Validator struct {
	rules []ValidationRule
}

// NewValidator returns a Validator with default rules applied.
func NewValidator() *Validator {
	v := &Validator{}
	v.rules = []ValidationRule{
		{
			Name: "non-empty-path",
			Check: func(s Secret) error {
				if strings.TrimSpace(s.Path) == "" {
					return fmt.Errorf("secret has an empty path")
				}
				return nil
			},
		},
		{
			Name: "non-empty-value",
			Check: func(s Secret) error {
				if strings.TrimSpace(s.Value) == "" {
					return fmt.Errorf("secret at path %q has an empty value", s.Path)
				}
				return nil
			},
		},
		{
			Name: "has-owner",
			Check: func(s Secret) error {
				if strings.TrimSpace(s.Owner) == "" {
					return fmt.Errorf("secret at path %q has no owner", s.Path)
				}
				return nil
			},
		},
	}
	return v
}

// AddRule appends a custom validation rule to the validator.
func (v *Validator) AddRule(rule ValidationRule) {
	if rule.Name == "" || rule.Check == nil {
		return
	}
	v.rules = append(v.rules, rule)
}

// Validate runs all rules against each secret and returns per-secret results.
func (v *Validator) Validate(secrets []Secret) []ValidationResult {
	results := make([]ValidationResult, 0, len(secrets))
	for _, s := range secrets {
		result := ValidationResult{Secret: s}
		for _, rule := range v.rules {
			if err := rule.Check(s); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("[%s] %s", rule.Name, err.Error()))
			}
		}
		results = append(results, result)
	}
	return results
}
