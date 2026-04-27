package audit

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// AnomalyType classifies the kind of anomaly detected.
type AnomalyType string

const (
	AnomalyDuplicateValue AnomalyType = "duplicate_value"
	AnomalyNoRotation    AnomalyType = "no_rotation"
	AnomalyShortSecret   AnomalyType = "short_secret"
)

// Anomaly describes a detected irregularity in a secret.
type Anomaly struct {
	Path    string
	Key     string
	Type    AnomalyType
	Detail  string
}

// AnomalyDetector scans secrets for anomalies.
type AnomalyDetector struct {
	minSecretLen    int
	maxAgeDaysNoRot int
}

// NewAnomalyDetector returns a detector with sensible defaults.
func NewAnomalyDetector(minSecretLen, maxAgeDaysNoRot int) *AnomalyDetector {
	if minSecretLen <= 0 {
		minSecretLen = 16
	}
	if maxAgeDaysNoRot <= 0 {
		maxAgeDaysNoRot = 90
	}
	return &AnomalyDetector{
		minSecretLen:    minSecretLen,
		maxAgeDaysNoRot: maxAgeDaysNoRot,
	}
}

// Detect analyses secrets and returns any anomalies found.
func (d *AnomalyDetector) Detect(secrets []Secret) []Anomaly {
	var anomalies []Anomaly
	seen := make(map[string]string) // value fingerprint -> first path

	for _, s := range secrets {
		for k, v := range s.Data {
			strVal, ok := v.(string)
			if !ok {
				continue
			}

			// Duplicate value detection
			fp := fmt.Sprintf("%s:%s", k, strVal)
			if first, dup := seen[fp]; dup {
				anomalies = append(anomalies, Anomaly{
					Path:   s.Path,
					Key:    k,
					Type:   AnomalyDuplicateValue,
					Detail: fmt.Sprintf("same value as %s", first),
				})
			} else {
				seen[fp] = s.Path
			}

			// Short secret detection
			if len(strVal) < d.minSecretLen {
				anomalies = append(anomalies, Anomaly{
					Path:   s.Path,
					Key:    k,
					Type:   AnomalyShortSecret,
					Detail: fmt.Sprintf("length %d below minimum %d", len(strVal), d.minSecretLen),
				})
			}
		}

		// No-rotation detection
		if s.AgeDays() > float64(d.maxAgeDaysNoRot) {
			anomalies = append(anomalies, Anomaly{
				Path:   s.Path,
				Key:    "",
				Type:   AnomalyNoRotation,
				Detail: fmt.Sprintf("not rotated in %.0f days (max %d)", s.AgeDays(), d.maxAgeDaysNoRot),
			})
		}
	}

	sort.Slice(anomalies, func(i, j int) bool {
		if anomalies[i].Path != anomalies[j].Path {
			return anomalies[i].Path < anomalies[j].Path
		}
		return anomalies[i].Type < anomalies[j].Type
	})
	return anomalies
}

// WriteAnomalies writes anomalies in a human-readable format to w.
func WriteAnomalies(w io.Writer, anomalies []Anomaly) {
	if len(anomalies) == 0 {
		fmt.Fprintln(w, "No anomalies detected.")
		return
	}
	fmt.Fprintf(w, "%-12s  %-40s  %-10s  %s\n", "TYPE", "PATH", "KEY", "DETAIL")
	fmt.Fprintln(w, strings.Repeat("-", 80))
	for _, a := range anomalies {
		fmt.Fprintf(w, "%-12s  %-40s  %-10s  %s\n", a.Type, a.Path, a.Key, a.Detail)
	}
}
