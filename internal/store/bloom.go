package store

import (
	"sync"

	bloom "github.com/bits-and-blooms/bloom/v3"
)

// repBloom is the reputation store's negative pre-filter (spec §11.3).
// MightContain returning false means the IP is definitely absent from BadgerDB;
// true means it may be present. False positives cause a redundant DB read;
// false negatives are impossible by design.
type repBloom struct {
	mu sync.RWMutex
	f  *bloom.BloomFilter
}

const (
	bloomCapacity uint    = 1_000_000 // ~1.2 MB at 1% FPR; degrades gracefully beyond this
	bloomFPR      float64 = 0.01
)

func newBloom() *repBloom {
	return &repBloom{f: bloom.NewWithEstimates(bloomCapacity, bloomFPR)}
}

func (b *repBloom) Add(ip string) {
	b.mu.Lock()
	b.f.AddString(ip)
	b.mu.Unlock()
}

func (b *repBloom) MightContain(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.f.TestString(ip)
}
