package rules

import (
	"testing"
	"time"
)

func TestBurstCount_Empty(t *testing.T) {
	b := NewBurstStore()
	now := time.Now()
	if got := b.Count("1.2.3.4", "ssh-probe", time.Minute, now); got != 0 {
		t.Errorf("empty store: got %d, want 0", got)
	}
}

func TestBurstCount_WithinWindow(t *testing.T) {
	b := NewBurstStore()
	base := time.Now()
	b.Record("1.2.3.4", "ssh-probe", base.Add(-30*time.Second))
	b.Record("1.2.3.4", "ssh-probe", base.Add(-10*time.Second))
	b.Record("1.2.3.4", "ssh-probe", base)

	got := b.Count("1.2.3.4", "ssh-probe", time.Minute, base)
	if got != 3 {
		t.Errorf("within window: got %d, want 3", got)
	}
}

func TestBurstCount_Eviction(t *testing.T) {
	b := NewBurstStore()
	base := time.Now()
	b.Record("1.2.3.4", "ssh-probe", base.Add(-2*time.Minute))  // outside 1m window
	b.Record("1.2.3.4", "ssh-probe", base.Add(-30*time.Second)) // inside
	b.Record("1.2.3.4", "ssh-probe", base)                      // inside

	got := b.Count("1.2.3.4", "ssh-probe", time.Minute, base)
	if got != 2 {
		t.Errorf("eviction: got %d, want 2", got)
	}
}

func TestBurstCount_DifferentReasonIsolated(t *testing.T) {
	b := NewBurstStore()
	base := time.Now()
	b.Record("1.2.3.4", "ssh-probe", base)
	b.Record("1.2.3.4", "smtp-auth-bruteforce", base)

	if got := b.Count("1.2.3.4", "ssh-probe", time.Minute, base); got != 1 {
		t.Errorf("ssh-probe: got %d, want 1", got)
	}
	if got := b.Count("1.2.3.4", "smtp-auth-bruteforce", time.Minute, base); got != 1 {
		t.Errorf("smtp: got %d, want 1", got)
	}
}

func TestBurstCount_EvictThenAppend(t *testing.T) {
	b := NewBurstStore()
	base := time.Now()
	// Record an old event that will be evicted
	b.Record("1.2.3.4", "ssh-probe", base.Add(-2*time.Minute))
	// Evict it
	if got := b.Count("1.2.3.4", "ssh-probe", time.Minute, base); got != 0 {
		t.Fatalf("after eviction: got %d, want 0", got)
	}
	// Record a new event after eviction
	b.Record("1.2.3.4", "ssh-probe", base)
	if got := b.Count("1.2.3.4", "ssh-probe", time.Minute, base); got != 1 {
		t.Errorf("after evict-then-append: got %d, want 1", got)
	}
}
