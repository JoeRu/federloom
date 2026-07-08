package node

import (
	"sync"
	"time"
)

// dedupKey identifies an event by the fields the originator's signature covers,
// so a re-emitted copy (which only differs in OriginTrace) yields the same key.
func dedupKey(reporterID, ip, reason string, ts time.Time) string {
	return reporterID + "|" + ip + "|" + reason + "|" + ts.UTC().Format(time.RFC3339Nano)
}

// dedupCache is a bounded, TTL'd set of event keys. Seen marks a key and reports
// whether it was already present. First-seen wins: the caller processes and
// (on a bridge) re-emits only when Seen returns false.
type dedupCache struct {
	mu   sync.Mutex
	max  int
	ttl  time.Duration
	seen map[string]time.Time // key -> insertion time
}

func newDedupCache(max int, ttl time.Duration) *dedupCache {
	return &dedupCache{max: max, ttl: ttl, seen: make(map[string]time.Time)}
}

// Seen returns true if key was already present (and unexpired); otherwise it
// inserts key and returns false. Expired entries are treated as absent.
func (d *dedupCache) Seen(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if at, ok := d.seen[key]; ok && now.Sub(at) < d.ttl {
		return true
	}
	// Insert (or refresh an expired entry). Evict if over bound.
	if len(d.seen) >= d.max {
		d.evictOldestLocked(now)
	}
	d.seen[key] = now
	return false
}

// evictOldestLocked drops expired entries first, then the single oldest if still
// at capacity. Caller holds d.mu.
func (d *dedupCache) evictOldestLocked(now time.Time) {
	for k, at := range d.seen {
		if now.Sub(at) >= d.ttl {
			delete(d.seen, k)
		}
	}
	if len(d.seen) < d.max {
		return
	}
	var oldestKey string
	var oldest time.Time
	first := true
	for k, at := range d.seen {
		if first || at.Before(oldest) {
			oldest, oldestKey, first = at, k, false
		}
	}
	if oldestKey != "" {
		delete(d.seen, oldestKey)
	}
}

func (d *dedupCache) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}
