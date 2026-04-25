package audit

import (
	"testing"
	"time"
)

func TestSecret_AgeDays(t *testing.T) {
	s := Secret{CreatedAt: time.Now().Add(-72 * time.Hour)}
	if got := s.AgeDays(); got != 3 {
		t.Errorf("AgeDays() = %d, want 3", got)
	}
}

func TestSecret_AgeDays_Zero(t *testing.T) {
	s := Secret{CreatedAt: time.Now()}
	if got := s.AgeDays(); got != 0 {
		t.Errorf("AgeDays() = %d, want 0", got)
	}
}

func TestSecret_IsExpired_NoExpiry(t *testing.T) {
	s := Secret{}
	if s.IsExpired() {
		t.Error("expected IsExpired() = false when ExpiresAt is zero")
	}
}

func TestSecret_IsExpired_Future(t *testing.T) {
	s := Secret{ExpiresAt: time.Now().Add(24 * time.Hour)}
	if s.IsExpired() {
		t.Error("expected IsExpired() = false for future expiry")
	}
}

func TestSecret_IsExpired_Past(t *testing.T) {
	s := Secret{ExpiresAt: time.Now().Add(-1 * time.Hour)}
	if !s.IsExpired() {
		t.Error("expected IsExpired() = true for past expiry")
	}
}

func TestSecret_ExpiresWithin_NoExpiry(t *testing.T) {
	s := Secret{}
	if s.ExpiresWithin(48 * time.Hour) {
		t.Error("expected ExpiresWithin() = false when no expiry set")
	}
}

func TestSecret_ExpiresWithin_Soon(t *testing.T) {
	s := Secret{ExpiresAt: time.Now().Add(12 * time.Hour)}
	if !s.ExpiresWithin(24 * time.Hour) {
		t.Error("expected ExpiresWithin(24h) = true when expiry is 12h away")
	}
}

func TestSecret_ExpiresWithin_Far(t *testing.T) {
	s := Secret{ExpiresAt: time.Now().Add(72 * time.Hour)}
	if s.ExpiresWithin(24 * time.Hour) {
		t.Error("expected ExpiresWithin(24h) = false when expiry is 72h away")
	}
}
