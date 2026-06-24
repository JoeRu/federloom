# Phase 3a — Bloom Filter Pre-filter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bloom filter negative pre-filter inside `BadgerStore` so `GetScore` skips the BadgerDB read for IPs that are definitely absent from the reputation store (spec §11.3).

**Architecture:** An unexported `repBloom` struct wraps `github.com/bits-and-blooms/bloom/v3` with a `sync.RWMutex`. `BadgerStore` gains a `bloom *repBloom` field populated by a single `ScanScores` pass at `Open()` time; `GetScore` returns a zero record immediately when `MightContain` returns false; `PutScore` calls `bloom.Add` after every successful write. No caller outside `internal/store` is aware the filter exists.

**Tech Stack:** Go 1.25, `github.com/bits-and-blooms/bloom/v3`, `github.com/dgraph-io/badger/v4` (existing).

## Global Constraints

- Module: `github.com/JoeRu/federloom`, Go 1.25
- New dependency: `github.com/bits-and-blooms/bloom/v3` — activate via `go get`, do not hand-edit `go.mod`
- `repBloom` is unexported — no public types added to the `store` package
- Bloom capacity: constant `bloomCapacity uint = 1_000_000`; FPR: constant `bloomFPR float64 = 0.01`
- Thread safety: `sync.RWMutex` — `RLock` for `MightContain`, `Lock` for `Add`
- `GetScore` early-return on `!MightContain`: returns `ScoreRecord{}, nil` (zero value, nil error)
- `PutScore` calls `s.bloom.Add(ip)` after the BadgerDB write succeeds
- `Open()` builds bloom via one `ScanScores` pass after opening BadgerDB
- No config knob, no Prometheus metrics, no periodic rebuild — YAGNI
- Test package: `package store_test` (external, matching existing `store_test.go`)
- Conventional Commits: `feat(store):` prefix
- Never commit secrets or generated binaries

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `go.mod` + `go.sum` | Add `github.com/bits-and-blooms/bloom/v3` via `go get` |
| Create | `internal/store/bloom.go` | `repBloom` struct, `newBloom()`, `Add`, `MightContain` |
| Modify | `internal/store/store.go` | `bloom` field on `BadgerStore`; bloom init in `Open`; gate in `GetScore`; update in `PutScore` |
| Modify | `internal/store/store_test.go` | Three new bloom integration tests |

---

## Task 1: repBloom wrapper + dependency

**Files:**
- Modify: `go.mod`, `go.sum` (via `go get`)
- Create: `internal/store/bloom.go`

**Interfaces:**
- Produces:
  - `func newBloom() *repBloom`
  - `func (b *repBloom) Add(ip string)`
  - `func (b *repBloom) MightContain(ip string) bool`
  - constants `bloomCapacity uint = 1_000_000` and `bloomFPR float64 = 0.01`

- [ ] **Step 1: Activate the dependency**

```bash
cd /root/federloom
go get github.com/bits-and-blooms/bloom/v3
go mod tidy
```

Expected: `go.mod` now has `github.com/bits-and-blooms/bloom/v3` in the `require` block; `go.sum` updated. No compile errors.

- [ ] **Step 2: Verify existing tests still pass**

```bash
go test ./internal/store/... -v
```

Expected: all 5 existing tests pass (`TestGetScoreMissing`, `TestPutGetRoundTrip`, `TestDeleteScore`, `TestScanScores`, `TestScoreRecordTrustFieldsRoundTrip`). The new dependency has not changed any behaviour.

- [ ] **Step 3: Create `internal/store/bloom.go`**

```go
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
```

- [ ] **Step 4: Verify the package compiles**

```bash
go build ./internal/store/...
```

Expected: no errors. `bloom.go` is dead code until Task 2 wires it in — that is expected.

- [ ] **Step 5: Run full test suite to check for regressions**

```bash
go test ./...
```

Expected: all packages pass.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/store/bloom.go
git commit -m "feat(store): add repBloom wrapper + activate bits-and-blooms/bloom/v3 (spec §11.3)"
```

---

## Task 2: Wire bloom into BadgerStore + integration tests

**Files:**
- Modify: `internal/store/store.go`
- Modify: `internal/store/store_test.go`

**Interfaces:**
- Consumes: `newBloom() *repBloom`, `(*repBloom).Add`, `(*repBloom).MightContain` (Task 1)
- Produces: `BadgerStore.GetScore` returns `ScoreRecord{}, nil` immediately when bloom says the IP is definitely absent; `BadgerStore.PutScore` updates bloom after every successful write; `BadgerStore.Open` rebuilds bloom from existing entries.

- [ ] **Step 1: Write the three failing tests**

Add to the bottom of `internal/store/store_test.go`:

```go
func TestBloom_UnknownIPReturnsZero(t *testing.T) {
	s := openTestStore(t)
	rec, err := s.GetScore("203.0.113.1")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if rec.Score != 0 || !rec.LastSeen.IsZero() {
		t.Errorf("expected zero ScoreRecord for unknown IP, got %+v", rec)
	}
}

func TestBloom_NoFalseNegative(t *testing.T) {
	s := openTestStore(t)
	want := store.ScoreRecord{
		Score:    55,
		LastSeen: time.Now().Truncate(time.Second),
	}
	if err := s.PutScore("198.51.100.7", want, 24*time.Hour); err != nil {
		t.Fatalf("PutScore: %v", err)
	}
	got, err := s.GetScore("198.51.100.7")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if got.Score != want.Score {
		t.Errorf("Score: got %v, want %v — bloom false negative", got.Score, want.Score)
	}
}

func TestBloom_RebuildOnReopen(t *testing.T) {
	dir := t.TempDir()

	// First instance: write an entry and close.
	s1, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open s1: %v", err)
	}
	rec := store.ScoreRecord{Score: 99, LastSeen: time.Now().Truncate(time.Second)}
	if err := s1.PutScore("10.0.0.1", rec, 24*time.Hour); err != nil {
		t.Fatalf("PutScore: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close s1: %v", err)
	}

	// Second instance: bloom must be rebuilt from the startup scan.
	s2, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open s2: %v", err)
	}
	defer s2.Close()

	got, err := s2.GetScore("10.0.0.1")
	if err != nil {
		t.Fatalf("GetScore after reopen: %v", err)
	}
	if got.Score != 99 {
		t.Errorf("Score: got %v, want 99 — bloom not rebuilt from DB on reopen", got.Score)
	}
}
```

- [ ] **Step 2: Run the new tests to verify they pass before any store changes**

```bash
go test ./internal/store/... -run 'TestBloom' -v
```

`TestBloom_UnknownIPReturnsZero` passes already (existing behaviour — `GetScore` returns zero for absent IPs). `TestBloom_NoFalseNegative` passes already (PutScore+GetScore round-trip works). `TestBloom_RebuildOnReopen` passes already (BadgerDB persists data; GetScore finds it on reopen).

All three should PASS here — they test the *correctness contract*, not the bloom path. They are regression guards: they must continue to pass after we wire in the bloom filter in the next steps.

- [ ] **Step 3: Add `bloom` field to `BadgerStore` and update `Open`**

In `internal/store/store.go`, replace the `BadgerStore` struct and `Open` function with:

```go
// BadgerStore wraps BadgerDB for reputation persistence.
type BadgerStore struct {
	db    *badger.DB
	bloom *repBloom
}

// Open opens (or creates) a BadgerDB at dir and rebuilds the bloom pre-filter
// from existing entries.
func Open(dir string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(dir).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("store: open badger at %q: %w", dir, err)
	}
	s := &BadgerStore{db: db, bloom: newBloom()}
	_ = s.ScanScores(func(ip string, _ ScoreRecord) error {
		s.bloom.Add(ip)
		return nil
	})
	return s, nil
}
```

- [ ] **Step 4: Gate `GetScore` with the bloom check**

Replace the existing `GetScore` function body — add the bloom early-return at the top:

```go
// GetScore returns the ScoreRecord for ip, or a zero ScoreRecord if not found.
// Callers check rec.LastSeen.IsZero() to detect missing entries.
func (s *BadgerStore) GetScore(ip string) (ScoreRecord, error) {
	if !s.bloom.MightContain(ip) {
		return ScoreRecord{}, nil // definitely absent; skip DB read
	}
	var rec ScoreRecord
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(ip))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &rec)
		})
	})
	if err != nil {
		return ScoreRecord{}, fmt.Errorf("store: get %q: %w", ip, err)
	}
	return rec, nil
}
```

- [ ] **Step 5: Update `PutScore` to add to the bloom after a successful write**

Replace the existing `PutScore` function body:

```go
// PutScore persists rec for ip with the given TTL.
func (s *BadgerStore) PutScore(ip string, rec ScoreRecord, ttl time.Duration) error {
	val, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("store: marshal %q: %w", ip, err)
	}
	if err := s.db.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry([]byte(ip), val).WithTTL(ttl)
		return txn.SetEntry(entry)
	}); err != nil {
		return err
	}
	s.bloom.Add(ip)
	return nil
}
```

- [ ] **Step 6: Run all store tests**

```bash
go test ./internal/store/... -v
```

Expected: all 8 tests pass (5 existing + 3 new bloom tests). No failures.

- [ ] **Step 7: Run full suite**

```bash
go test ./...
```

Expected: all packages pass.

- [ ] **Step 8: Build both binaries**

```bash
make build
```

Expected: `bin/federloomd` and `bin/federloomctl` build successfully.

- [ ] **Step 9: Commit**

```bash
git add internal/store/store.go internal/store/store_test.go
git commit -m "feat(store): bloom pre-filter in GetScore + PutScore; rebuild on Open (spec §11.3)"
```

---

## Self-Review

**Spec coverage:**

| Requirement | Task |
|---|---|
| `repBloom` unexported, wraps `bits-and-blooms/bloom/v3` | Task 1 |
| `newBloom()`, `Add(ip)`, `MightContain(ip) bool` | Task 1 |
| `bloomCapacity = 1_000_000`, `bloomFPR = 0.01` | Task 1 |
| `sync.RWMutex` — RLock for reads, Lock for writes | Task 1 |
| `BadgerStore.bloom *repBloom` field | Task 2 |
| `Open()` rebuilds bloom via one `ScanScores` pass | Task 2 |
| `GetScore` returns `ScoreRecord{}, nil` when `!MightContain` | Task 2 |
| `PutScore` calls `bloom.Add` after successful DB write | Task 2 |
| Three integration tests: UnknownIPReturnsZero, NoFalseNegative, RebuildOnReopen | Task 2 |
| No config knob, no metrics, no periodic rebuild | Both tasks — nothing added |
| No changes outside `internal/store` | Both tasks — verified |
