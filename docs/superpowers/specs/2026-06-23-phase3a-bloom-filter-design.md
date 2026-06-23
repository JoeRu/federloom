# Phase 3a — Bloom Filter Pre-filter Design

**Date:** 2026-06-23
**Status:** Approved — ready for implementation planning
**Scope:** Add a bloom filter negative pre-filter to `BadgerStore` so `GetScore` skips the BadgerDB read for IPs that are definitely absent from the reputation store (spec §11.3).

---

## Context

`BadgerStore.GetScore` currently does a full BadgerDB key lookup on every call. For IPs that have never been seen (the common case when a new connection arrives), this read always returns not-found. A bloom filter intercepts that path and short-circuits it: if the filter says the IP is definitely absent, skip the DB read entirely and return a zero `ScoreRecord` immediately.

This is a pure local optimisation. No public API changes. No callers are aware the filter exists.

---

## Architecture

Three files change. No other packages are touched.

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `go.mod` | Activate `github.com/bits-and-blooms/bloom/v3` (currently a commented-out placeholder) |
| Create | `internal/store/bloom.go` | Unexported `repBloom` struct — thread-safe wrapper around the library with `Add(ip)` and `MightContain(ip) bool` |
| Modify | `internal/store/store.go` | Add `bloom *repBloom` field to `BadgerStore`; populate in `Open()`; gate `GetScore`; update in `PutScore` |
| Modify | `internal/store/store_test.go` | Three new integration tests |

---

## Data Model

### `repBloom` (`internal/store/bloom.go`)

```go
type repBloom struct {
    mu sync.RWMutex
    f  *bloom.BloomFilter
}

const (
    bloomCapacity uint    = 1_000_000 // entries; ~1.2 MB; FPR degrades gracefully beyond this
    bloomFPR      float64 = 0.01      // 1% false-positive rate
)

func newBloom() *repBloom
func (b *repBloom) Add(ip string)
func (b *repBloom) MightContain(ip string) bool
```

No exported types. `repBloom` is an implementation detail of `BadgerStore`.

---

## Bloom Lifecycle

### Sizing

Fixed: 1,000,000 entries at 1% FPR (~1.2 MB). No config knob this phase. If the store grows beyond 1M entries the FPR degrades gracefully — false positives cause extra DB reads but never skip an entry that exists. A daemon restart rebuilds the filter from scratch.

### Startup rebuild (`Open`)

After opening BadgerDB, scan once with `ScanScores` and call `bloom.Add(ip)` for every existing entry. O(n) over store size, runs once. No second scan; no separate count pass.

```go
s.bloom = newBloom()
_ = s.ScanScores(func(ip string, _ ScoreRecord) error {
    s.bloom.Add(ip)
    return nil
})
```

### Query gate (`GetScore`)

```go
func (s *BadgerStore) GetScore(ip string) (ScoreRecord, error) {
    if !s.bloom.MightContain(ip) {
        return ScoreRecord{}, nil // definitely absent; skip DB read
    }
    // existing BadgerDB lookup unchanged
}
```

A false positive (bloom says "maybe" for an IP not in DB) causes one unnecessary DB read and returns a zero record — correct behaviour.

### Update (`PutScore`)

After writing to BadgerDB, call `s.bloom.Add(ip)`. Adding to a bloom is idempotent.

### Decay / TTL interaction

When BadgerDB TTL-expires a score entry the bloom filter retains that IP (bloom filters have no deletion). `GetScore` for a decayed IP passes the bloom gate, does a real DB lookup, and returns a zero record. This is correct — a decayed IP is treated as new/unseen, which matches the decay-as-deletion semantic (spec §9).

---

## Testing

New tests in `internal/store/` (same package, alongside `store_test.go`):

### `TestBloom_UnknownIPReturnsZero`
Open a fresh store. Call `GetScore("1.2.3.4")`. Assert zero `ScoreRecord` and nil error. Confirms the bloom gate returns the correct zero value for absent IPs.

### `TestBloom_NoFalseNegative`
`PutScore("1.2.3.4", rec, ttl)` then `GetScore("1.2.3.4")`. Assert the full record is returned. Confirms bloom never blocks a lookup for an IP that actually exists in the store.

### `TestBloom_RebuildOnReopen`
`PutScore` in one `BadgerStore` instance, close it, open a new instance at the same `t.TempDir()` path, call `GetScore`, assert the record is present. Confirms the startup scan populates the bloom from an existing DB.

No test asserts "the DB read was skipped" — that would require a counter, which is excluded this phase. These tests verify the correctness contract: the bloom is an optimisation, not a behaviour change.

---

## What is explicitly out of scope

- Prometheus metrics for bloom hits/misses (Phase 4 or later)
- Configurable FPR or capacity (`sync.bloom_fpr` config key deferred to Phase 3b when the `sync:` section is introduced)
- Periodic bloom rebuild to reclaim ghost entries from decayed IPs (restart is sufficient)
- Any changes to `node.go`, `reputation/`, or other callers
