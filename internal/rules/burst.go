package rules

import (
	"sync"
	"time"
)

// BurstStore tracks per-(ip,reason) event timestamps for sliding-window burst
// detection. State is in-memory only; resets on daemon restart.
type BurstStore struct {
	mu      sync.Mutex
	entries map[burstKey][]time.Time
}

type burstKey struct{ ip, reason string }

// NewBurstStore returns an empty BurstStore.
func NewBurstStore() *BurstStore {
	return &BurstStore{entries: make(map[burstKey][]time.Time)}
}

// Record appends now to the sliding window for (ip, reason).
func (b *BurstStore) Record(ip, reason string, now time.Time) {
	k := burstKey{ip, reason}
	b.mu.Lock()
	b.entries[k] = append(b.entries[k], now)
	b.mu.Unlock()
}

// Count returns how many events for (ip, reason) fall within [now-window, now].
// Evicts stale entries and compacts memory as a side effect (lazy GC — no background goroutine).
func (b *BurstStore) Count(ip, reason string, window time.Duration, now time.Time) int {
	k := burstKey{ip, reason}
	cutoff := now.Add(-window)
	b.mu.Lock()
	defer b.mu.Unlock()
	ts := b.entries[k]
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	live := append([]time.Time(nil), ts[i:]...)
	if len(live) == 0 {
		delete(b.entries, k)
		return 0
	}
	b.entries[k] = live
	return len(live)
}
