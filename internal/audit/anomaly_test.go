package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func anomalySecrets() []Secret {
	now := time.Now()
	old := now.AddDate(0, 0, -120)
	return []Secret{
		{
			Path:      "secret/app/db",
			CreatedAt: now.AddDate(0, 0, -5),
			Data:      map[string]interface{}{"password": "short"},
		},
		{
			Path:      "secret/app/api",
			CreatedAt: old,
			Data:      map[string]interface{}{"token": "averylongtokenvalue1234"},
		},
		{
			Path:      "secret/app/cache",
			CreatedAt: now.AddDate(0, 0, -3),
			Data:      map[string]interface{}{"token": "averylongtokenvalue1234"}, // duplicate value
		},
	}
}

func TestNewAnomalyDetector_Defaults(t *testing.T) {
	d := NewAnomalyDetector(0, 0)
	if d.minSecretLen != 16 {
		t.Errorf("expected default minSecretLen 16, got %d", d.minSecretLen)
	}
	if d.maxAgeDaysNoRot != 90 {
		t.Errorf("expected default maxAgeDaysNoRot 90, got %d", d.maxAgeDaysNoRot)
	}
}

func TestDetect_ShortSecret(t *testing.T) {
	d := NewAnomalyDetector(16, 90)
	anomalies := d.Detect(anomalySecrets())
	var found bool
	for _, a := range anomalies {
		if a.Type == AnomalyShortSecret && a.Path == "secret/app/db" {
			found = true
		}
	}
	if !found {
		t.Error("expected short secret anomaly for secret/app/db")
	}
}

func TestDetect_NoRotation(t *testing.T) {
	d := NewAnomalyDetector(16, 90)
	anomalies := d.Detect(anomalySecrets())
	var found bool
	for _, a := range anomalies {
		if a.Type == AnomalyNoRotation && a.Path == "secret/app/api" {
			found = true
		}
	}
	if !found {
		t.Error("expected no-rotation anomaly for secret/app/api")
	}
}

func TestDetect_DuplicateValue(t *testing.T) {
	d := NewAnomalyDetector(16, 90)
	anomalies := d.Detect(anomalySecrets())
	var found bool
	for _, a := range anomalies {
		if a.Type == AnomalyDuplicateValue {
			found = true
		}
	}
	if !found {
		t.Error("expected duplicate value anomaly")
	}
}

func TestDetect_NoAnomalies(t *testing.T) {
	d := NewAnomalyDetector(4, 200)
	secrets := []Secret{
		{
			Path:      "secret/clean",
			CreatedAt: time.Now().AddDate(0, 0, -10),
			Data:      map[string]interface{}{"key": "uniquevalue"},
		},
	}
	anomalies := d.Detect(secrets)
	if len(anomalies) != 0 {
		t.Errorf("expected no anomalies, got %d", len(anomalies))
	}
}

func TestWriteAnomalies_Empty(t *testing.T) {
	var buf bytes.Buffer
	WriteAnomalies(&buf, nil)
	if !strings.Contains(buf.String(), "No anomalies") {
		t.Error("expected 'No anomalies' message")
	}
}

func TestWriteAnomalies_WithResults(t *testing.T) {
	d := NewAnomalyDetector(16, 90)
	anomalies := d.Detect(anomalySecrets())
	var buf bytes.Buffer
	WriteAnomalies(&buf, anomalies)
	out := buf.String()
	if !strings.Contains(out, "TYPE") {
		t.Error("expected header row in output")
	}
	if !strings.Contains(out, "secret/app") {
		t.Error("expected path in output")
	}
}
