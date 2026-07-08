package node

import (
	"testing"
	"time"
)

func TestDedupSeenFirstThenRepeat(t *testing.T) {
	d := newDedupCache(100, time.Minute)
	now := time.Now()
	k := dedupKey("peerA", "1.2.3.4", "ssh-probe", now)
	if d.Seen(k, now) {
		t.Error("first Seen must return false (not seen before)")
	}
	if !d.Seen(k, now) {
		t.Error("second Seen must return true (already seen)")
	}
}

func TestDedupDistinctKeys(t *testing.T) {
	d := newDedupCache(100, time.Minute)
	now := time.Now()
	if d.Seen(dedupKey("peerA", "1.2.3.4", "ssh-probe", now), now) {
		t.Error("distinct key A wrongly seen")
	}
	if d.Seen(dedupKey("peerB", "1.2.3.4", "ssh-probe", now), now) {
		t.Error("distinct key B (different reporter) wrongly seen")
	}
}

func TestDedupTTLEviction(t *testing.T) {
	d := newDedupCache(100, time.Minute)
	t0 := time.Now()
	k := dedupKey("peerA", "1.2.3.4", "ssh-probe", t0)
	d.Seen(k, t0)
	// After the TTL window, the key is expired and treated as new again.
	if d.Seen(k, t0.Add(2*time.Minute)) {
		t.Error("key past TTL must be treated as not-seen")
	}
}

func TestDedupBoundEviction(t *testing.T) {
	d := newDedupCache(2, time.Hour)
	now := time.Now()
	d.Seen(dedupKey("p1", "1.1.1.1", "r", now), now)
	d.Seen(dedupKey("p2", "2.2.2.2", "r", now), now)
	d.Seen(dedupKey("p3", "3.3.3.3", "r", now), now) // triggers eviction of oldest
	if d.len() > 2 {
		t.Errorf("cache exceeded bound: len=%d, want <= 2", d.len())
	}
}
