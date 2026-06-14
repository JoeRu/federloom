package rules

import (
	"testing"
	"time"
)

func TestBurstCount_Empty(t *testing.T) {
	b := NewBurstStore()
	if got := b.Count("1.2.3.4", "ssh-probe", time.Minute); got != 0 {
		t.Errorf("empty store: got %d, want 0", got)
	}
}

func TestBurstCount_WithinWindow(t *testing.T) {
	b := NewBurstStore()
	now := time.Now()
	b.Record("1.2.3.4", "ssh-probe", now.Add(-30*time.Second))
	b.Record("1.2.3.4", "ssh-probe", now.Add(-10*time.Second))
	b.Record("1.2.3.4", "ssh-probe", now)

	got := b.Count("1.2.3.4", "ssh-probe", time.Minute)
	if got != 3 {
		t.Errorf("within window: got %d, want 3", got)
	}
}

func TestBurstCount_Eviction(t *testing.T) {
	b := NewBurstStore()
	now := time.Now()
	b.Record("1.2.3.4", "ssh-probe", now.Add(-2*time.Minute)) // outside 1m window
	b.Record("1.2.3.4", "ssh-probe", now.Add(-30*time.Second)) // inside
	b.Record("1.2.3.4", "ssh-probe", now)                      // inside

	got := b.Count("1.2.3.4", "ssh-probe", time.Minute)
	if got != 2 {
		t.Errorf("eviction: got %d, want 2", got)
	}
}

func TestBurstCount_DifferentReasonIsolated(t *testing.T) {
	b := NewBurstStore()
	now := time.Now()
	b.Record("1.2.3.4", "ssh-probe", now)
	b.Record("1.2.3.4", "smtp-auth-bruteforce", now)

	if got := b.Count("1.2.3.4", "ssh-probe", time.Minute); got != 1 {
		t.Errorf("ssh-probe: got %d, want 1", got)
	}
	if got := b.Count("1.2.3.4", "smtp-auth-bruteforce", time.Minute); got != 1 {
		t.Errorf("smtp: got %d, want 1", got)
	}
}
