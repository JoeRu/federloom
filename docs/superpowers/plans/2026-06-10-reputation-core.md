# Reputation Core + Cowrie Ingest + ipset/nftables Enforcement

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire a complete local reputation pipeline: Cowrie honeypot → exponential-decay/corroboration reputation engine (BadgerDB) → ipset or nftables enforcement, with P2P gossip events feeding the same pipeline, and swarmd driven by a YAML config file.

**Architecture:** `internal/ingest/honeypot.go` tails `cowrie.json` (JSONL). `internal/reputation` computes scores via lazy decay + logistic accumulation, backed by `internal/store` (BadgerDB, TTL = 3×half-life for GDPR compliance). `internal/enforce/ipset.go` and `nftables.go` shell out to the firewall tool. `internal/node/node.go` fans events from ingest sources + gossip transport into the reputation engine, then calls the enforce sink at threshold crossings. `cmd/swarmd/main.go` loads YAML config and launches `node.New(cfg)`.

**Tech Stack:** Go 1.25, `github.com/dgraph-io/badger/v4` (KV store), `gopkg.in/yaml.v3` (config), `/sbin/ipset`+`/sbin/iptables` or `/sbin/nft` (enforcement via `os/exec`), libp2p gossipsub (existing `internal/transport`).

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `go.mod` / `go.sum` | Modify | Add badger/v4, yaml.v3 |
| `internal/config/config.go` | Modify | Full config struct (store, reputation, ingest, enforce) + YAML load |
| `internal/store/store.go` | **Create** | BadgerDB wrapper: Open/Close, GetScore/PutScore/DeleteScore/ScanScores |
| `internal/reputation/decay.go` | Modify | Pure `decayScore(score, lastSeen, now, halfLife)` function |
| `internal/reputation/corroboration.go` | Modify | `containsString` helper used by engine |
| `internal/reputation/engine.go` | **Create** | `Engine`: Record() + Decay() — composition of store + decay + corroboration |
| `internal/enforce/plugin.go` | Modify | Sink interface: Name/Start/Block/Unblock/Close (replaces Apply) |
| `internal/enforce/neverblock.go` | Modify | `NeverBlockList`: RFC1918 + user list, `Contains(ip) bool` |
| `internal/enforce/ipset.go` | Modify | ipset backend: Start (create set + iptables rule), Block, Unblock |
| `internal/enforce/nftables.go` | Modify | nftables backend: Start (create table/set/rule), Block, Unblock |
| `internal/ingest/honeypot.go` | Modify | Cowrie JSONL tail: poll, parse, emit `proto.Event` via channel |
| `internal/node/node.go` | **Create** | Composition root: New(), Run(), processLocal/Remote, runDecay |
| `cmd/swarmd/main.go` | Modify | Add `--config`, load YAML, wire transport + node |
| `internal/config/config_test.go` | **Create** | Unit: defaults valid, YAML round-trip |
| `internal/reputation/decay_test.go` | **Create** | Unit: half-life math |
| `internal/reputation/corroboration_test.go` | **Create** | Unit: reporter dedup |
| `internal/ingest/honeypot_test.go` | **Create** | Unit: JSONL parsing |
| `test/integration/reputation_store_test.go` | **Create** | Integration: store + engine round-trips |
| `test/integration/pipeline_test.go` | **Create** | Integration: mock sink receives Block() after threshold |
| `test/adversarial/sybil_ingest_test.go` | **Create** | Adversarial: 50-peer sybil flood, score capped at 100 |
| `test/adversarial/poisoning_test.go` | **Create** | Adversarial: neverblock IP never reaches Block() |

---

### Task 1: Dependencies + Config

**Files:**
- Modify: `go.mod`, `go.sum`
- Modify: `internal/config/config.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Add dependencies**

```bash
cd /mnt/c/Users/johan/code/swarmguard
go get github.com/dgraph-io/badger/v4
go get gopkg.in/yaml.v3
```

Expected: both appear in `go.mod` require block, `go.sum` updated.

- [ ] **Step 2: Write the failing test**

Create `internal/config/config_test.go`:

```go
package config_test

import (
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
)

func TestDefaultsAreValid(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Reputation.HalfLife.Duration <= 0 {
		t.Fatal("expected positive half-life")
	}
	if cfg.Enforce.Backend == "" {
		t.Fatal("expected non-empty enforce backend")
	}
}

func TestLoadYAML(t *testing.T) {
	cfg, err := config.LoadYAML([]byte(`
reputation:
  half_life: 24h
  block_threshold: 80
  unblock_threshold: 55
  decay_interval: 30m
enforce:
  backend: nftables
  set_name: sg
ingest:
  honeypot:
    enabled: true
    log_file: /tmp/cowrie.json
    poll_interval: 500ms
store:
  dir: /tmp/sgtest
`))
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if cfg.Reputation.HalfLife.Duration != 24*time.Hour {
		t.Errorf("half_life: got %v, want 24h", cfg.Reputation.HalfLife.Duration)
	}
	if cfg.Enforce.Backend != "nftables" {
		t.Errorf("backend: got %q, want nftables", cfg.Enforce.Backend)
	}
	if !cfg.Ingest.Honeypot.Enabled {
		t.Error("expected honeypot.enabled = true")
	}
}
```

- [ ] **Step 3: Run to confirm failure**

```bash
go test ./internal/config/...
```

Expected: compile error — `config.Defaults` undefined.

- [ ] **Step 4: Implement config.go**

Replace `internal/config/config.go`:

```go
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration for YAML unmarshalling from strings like "7d", "24h".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("config: parse duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// Config is the top-level runtime configuration.
type Config struct {
	FederationMode string           `yaml:"federation_mode"`
	Store          StoreConfig      `yaml:"store"`
	Reputation     ReputationConfig `yaml:"reputation"`
	Ingest         IngestConfig     `yaml:"ingest"`
	Enforce        EnforceConfig    `yaml:"enforce"`
}

// StoreConfig configures the BadgerDB reputation store.
type StoreConfig struct {
	Dir string `yaml:"dir"`
}

// ReputationConfig tunes the scoring engine.
type ReputationConfig struct {
	HalfLife         Duration `yaml:"half_life"`
	BlockThreshold   float64  `yaml:"block_threshold"`
	UnblockThreshold float64  `yaml:"unblock_threshold"`
	DecayInterval    Duration `yaml:"decay_interval"`
}

// IngestConfig groups all ingest source configs.
type IngestConfig struct {
	Honeypot HoneypotConfig `yaml:"honeypot"`
}

// HoneypotConfig configures the Cowrie ingest adapter.
type HoneypotConfig struct {
	Enabled      bool     `yaml:"enabled"`
	LogFile      string   `yaml:"log_file"`
	PollInterval Duration `yaml:"poll_interval"`
}

// EnforceConfig selects and tunes the firewall backend.
type EnforceConfig struct {
	Backend        string   `yaml:"backend"`         // "ipset" | "nftables"
	SetName        string   `yaml:"set_name"`        // ipset set / nftables set name
	Chain          string   `yaml:"chain"`           // iptables chain (ipset backend)
	NftHook        string   `yaml:"nft_hook"`        // nftables hook: "input" | "forward"
	ExtraWhitelist []string `yaml:"extra_whitelist"` // additional CIDRs never blocked
}

// Defaults returns a Config with sensible production defaults.
func Defaults() *Config {
	return &Config{
		FederationMode: "solo",
		Store:          StoreConfig{Dir: "data/reputation"},
		Reputation: ReputationConfig{
			HalfLife:         Duration{7 * 24 * time.Hour},
			BlockThreshold:   75,
			UnblockThreshold: 60,
			DecayInterval:    Duration{time.Hour},
		},
		Enforce: EnforceConfig{
			Backend: "ipset",
			SetName: "swarmguard",
			Chain:   "DOCKER-USER",
			NftHook: "input",
		},
		Ingest: IngestConfig{
			Honeypot: HoneypotConfig{
				PollInterval: Duration{time.Second},
			},
		},
	}
}

// LoadYAML unmarshals YAML bytes into a Config, applying defaults for unset fields.
func LoadYAML(data []byte) (*Config, error) {
	cfg := Defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	return cfg, nil
}

// Load reads a YAML config file from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	return LoadYAML(data)
}
```

- [ ] **Step 5: Run tests — expect PASS**

```bash
go test ./internal/config/...
```

Expected: `ok github.com/JoeRu/swarmguard/internal/config`

- [ ] **Step 6: Verify build**

```bash
go build ./...
```

Expected: success (no new code calls `config.Load` yet).

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/config/
git update-index --chmod=-x internal/config/config_test.go
git commit -m "feat(config): full config struct with YAML loading and defaults"
```

---

### Task 2: BadgerDB Store

**Files:**
- Create: `internal/store/store.go`

- [ ] **Step 1: Write the failing test**

Create `internal/store/store_test.go`:

```go
package store_test

import (
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/store"
)

func openTestStore(t *testing.T) *store.BadgerStore {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestGetScoreMissing(t *testing.T) {
	s := openTestStore(t)
	rec, err := s.GetScore("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Score != 0 {
		t.Errorf("expected zero score, got %v", rec.Score)
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	s := openTestStore(t)
	want := store.ScoreRecord{
		Score:         42.5,
		Corroboration: 2,
		FirstSeen:     time.Now().Truncate(time.Second),
		LastSeen:      time.Now().Truncate(time.Second),
		Reasons:       []string{"ssh-probe"},
		ReporterIDs:   []string{"peer1", "peer2"},
	}
	if err := s.PutScore("1.2.3.4", want, 24*time.Hour); err != nil {
		t.Fatalf("PutScore: %v", err)
	}
	got, err := s.GetScore("1.2.3.4")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if got.Score != want.Score {
		t.Errorf("Score: got %v, want %v", got.Score, want.Score)
	}
	if got.Corroboration != want.Corroboration {
		t.Errorf("Corroboration: got %v, want %v", got.Corroboration, want.Corroboration)
	}
}

func TestDeleteScore(t *testing.T) {
	s := openTestStore(t)
	_ = s.PutScore("1.2.3.4", store.ScoreRecord{Score: 10}, 24*time.Hour)
	if err := s.DeleteScore("1.2.3.4"); err != nil {
		t.Fatalf("DeleteScore: %v", err)
	}
	rec, err := s.GetScore("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error after delete: %v", err)
	}
	if rec.Score != 0 {
		t.Errorf("expected zero score after delete, got %v", rec.Score)
	}
}

func TestScanScores(t *testing.T) {
	s := openTestStore(t)
	_ = s.PutScore("1.1.1.1", store.ScoreRecord{Score: 10}, 24*time.Hour)
	_ = s.PutScore("2.2.2.2", store.ScoreRecord{Score: 20}, 24*time.Hour)
	seen := map[string]float64{}
	err := s.ScanScores(func(ip string, r store.ScoreRecord) error {
		seen[ip] = r.Score
		return nil
	})
	if err != nil {
		t.Fatalf("ScanScores: %v", err)
	}
	if len(seen) != 2 {
		t.Errorf("expected 2 entries, got %d", len(seen))
	}
	if seen["1.1.1.1"] != 10 || seen["2.2.2.2"] != 20 {
		t.Errorf("wrong scores: %v", seen)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/store/...
```

Expected: compile error — `store.Open` undefined.

- [ ] **Step 3: Implement store.go**

Create `internal/store/store.go`:

```go
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// ScoreRecord is the internal on-disk reputation record for one IP.
// ReporterIDs is tracking metadata never sent on the wire.
type ScoreRecord struct {
	Score         float64   `json:"score"`
	Corroboration int       `json:"corroboration"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Reasons       []string  `json:"reasons"`
	ReporterIDs   []string  `json:"reporter_ids"`
}

// BadgerStore wraps BadgerDB for reputation persistence.
type BadgerStore struct {
	db *badger.DB
}

// Open opens (or creates) a BadgerDB at dir.
func Open(dir string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(dir).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("store: open badger at %q: %w", dir, err)
	}
	return &BadgerStore{db: db}, nil
}

// Close releases the BadgerDB resources.
func (s *BadgerStore) Close() error { return s.db.Close() }

// GetScore returns the ScoreRecord for ip, or a zero ScoreRecord if not found.
func (s *BadgerStore) GetScore(ip string) (ScoreRecord, error) {
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

// PutScore persists rec for ip with the given TTL.
func (s *BadgerStore) PutScore(ip string, rec ScoreRecord, ttl time.Duration) error {
	val, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("store: marshal %q: %w", ip, err)
	}
	return s.db.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry([]byte(ip), val).WithTTL(ttl)
		return txn.SetEntry(entry)
	})
}

// DeleteScore removes the record for ip.
func (s *BadgerStore) DeleteScore(ip string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(ip))
	})
}

// ScanScores calls fn for every stored IP. Stops on first error from fn.
func (s *BadgerStore) ScanScores(fn func(ip string, r ScoreRecord) error) error {
	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			ip := string(item.KeyCopy(nil))
			var rec ScoreRecord
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &rec)
			}); err != nil {
				return err
			}
			if err := fn(ip, rec); err != nil {
				return err
			}
		}
		return nil
	})
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test ./internal/store/...
```

Expected: `ok github.com/JoeRu/swarmguard/internal/store`

- [ ] **Step 5: Commit**

```bash
git add internal/store/
git update-index --chmod=-x internal/store/store.go internal/store/store_test.go
git commit -m "feat(store): BadgerDB wrapper with GetScore/PutScore/DeleteScore/ScanScores"
```

---

### Task 3: Reputation Decay

**Files:**
- Modify: `internal/reputation/decay.go`
- Create: `internal/reputation/decay_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/reputation/decay_test.go`:

```go
package reputation_test

import (
	"math"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/reputation"
)

func TestDecayAtZeroElapsed(t *testing.T) {
	now := time.Now()
	got := reputation.DecayScore(100, now, now, 7*24*time.Hour)
	if math.Abs(got-100) > 0.001 {
		t.Errorf("expected ~100, got %v", got)
	}
}

func TestDecayAtOneHalfLife(t *testing.T) {
	halfLife := 7 * 24 * time.Hour
	lastSeen := time.Now().Add(-halfLife)
	got := reputation.DecayScore(100, lastSeen, time.Now(), halfLife)
	if math.Abs(got-50) > 0.5 {
		t.Errorf("expected ~50 at one half-life, got %v", got)
	}
}

func TestDecayAtTwoHalfLives(t *testing.T) {
	halfLife := 7 * 24 * time.Hour
	lastSeen := time.Now().Add(-2 * halfLife)
	got := reputation.DecayScore(100, lastSeen, time.Now(), halfLife)
	if math.Abs(got-25) > 0.5 {
		t.Errorf("expected ~25 at two half-lives, got %v", got)
	}
}

func TestDecayZeroScoreStaysZero(t *testing.T) {
	lastSeen := time.Now().Add(-24 * time.Hour)
	got := reputation.DecayScore(0, lastSeen, time.Now(), 7*24*time.Hour)
	if got != 0 {
		t.Errorf("expected 0, got %v", got)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/reputation/...
```

Expected: compile error — `reputation.DecayScore` undefined.

- [ ] **Step 3: Implement decay.go**

Replace `internal/reputation/decay.go`:

```go
package reputation

import (
	"math"
	"time"
)

// DecayScore computes the decayed score using the formula:
//
//	score(t) = score₀ × exp(−ln2 × Δt / halfLife)
//
// Exported for unit testing. Engine.Decay calls this with time.Now().
func DecayScore(score float64, lastSeen, now time.Time, halfLife time.Duration) float64 {
	if score == 0 || halfLife <= 0 {
		return score
	}
	elapsed := now.Sub(lastSeen).Seconds()
	return score * math.Exp(-math.Log(2)*elapsed/halfLife.Seconds())
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test ./internal/reputation/...
```

Expected: `ok github.com/JoeRu/swarmguard/internal/reputation`

- [ ] **Step 5: Commit**

```bash
git add internal/reputation/decay.go internal/reputation/decay_test.go
git update-index --chmod=-x internal/reputation/decay.go internal/reputation/decay_test.go
git commit -m "feat(reputation): implement exponential decay (spec §4.3, §8)"
```

---

### Task 4: Reputation Engine

**Files:**
- Modify: `internal/reputation/corroboration.go`
- Create: `internal/reputation/engine.go`
- Create: `internal/reputation/corroboration_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/reputation/corroboration_test.go`:

```go
package reputation_test

import (
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
)

func openEngine(t *testing.T) *reputation.Engine {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return reputation.New(s, 7*24*time.Hour)
}

func TestRecordIncreasesScore(t *testing.T) {
	e := openEngine(t)
	score, err := e.Record("1.2.3.4", "ssh-probe", "peer1", 1.0)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if score <= 0 {
		t.Errorf("expected positive score, got %v", score)
	}
}

func TestSameReporterDoesNotIncreaseCorroboration(t *testing.T) {
	e := openEngine(t)
	_, _ = e.Record("1.2.3.4", "ssh-probe", "peer1", 1.0)
	_, _ = e.Record("1.2.3.4", "ssh-probe", "peer1", 1.0)
	rec, err := e.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Corroboration != 1 {
		t.Errorf("expected corroboration=1 for same reporter, got %d", rec.Corroboration)
	}
}

func TestTwoReportersIncreasesCorroboration(t *testing.T) {
	e := openEngine(t)
	_, _ = e.Record("1.2.3.4", "ssh-probe", "peer1", 1.0)
	_, _ = e.Record("1.2.3.4", "ssh-probe", "peer2", 1.0)
	rec, err := e.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Corroboration != 2 {
		t.Errorf("expected corroboration=2, got %d", rec.Corroboration)
	}
}

func TestScoreNeverExceeds100(t *testing.T) {
	e := openEngine(t)
	for i := 0; i < 100; i++ {
		score, err := e.Record("1.2.3.4", "ssh-auth-success", "peer1", 1.0)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if score > 100 {
			t.Fatalf("score exceeded 100: %v at iteration %d", score, i)
		}
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/reputation/...
```

Expected: compile error — `reputation.New` undefined.

- [ ] **Step 3: Implement corroboration.go**

Replace `internal/reputation/corroboration.go`:

```go
package reputation

// containsString returns true if s is in slice.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Implement engine.go**

Create `internal/reputation/engine.go`:

```go
package reputation

import (
	"fmt"
	"time"

	"github.com/JoeRu/swarmguard/internal/store"
)

// reportWeight maps event reason to score contribution weight.
var reportWeight = map[string]float64{
	"ssh-auth-success":      40,
	"ssh-auth-bruteforce":   10,
	"ssh-post-auth-command": 10,
	"ssh-probe":             2,
	"ssh-unknown":           2,
}

func weightFor(reason string) float64 {
	if w, ok := reportWeight[reason]; ok {
		return w
	}
	return 2
}

// Engine computes IP reputation scores using lazy decay and logistic accumulation.
type Engine struct {
	store    *store.BadgerStore
	halfLife time.Duration
}

// New creates an Engine backed by s with the given half-life for decay.
func New(s *store.BadgerStore, halfLife time.Duration) *Engine {
	return &Engine{store: s, halfLife: halfLife}
}

// Record applies one observation to ip's score and returns the new score.
// trust is 1.0 for local ground-truth sources, 0.3 for remote peers.
func (e *Engine) Record(ip, reason, reporterID string, trust float64) (float64, error) {
	rec, err := e.store.GetScore(ip)
	if err != nil {
		return 0, fmt.Errorf("reputation: get %q: %w", ip, err)
	}

	now := time.Now()

	// Lazy decay: apply time-based decay since last observation.
	if !rec.LastSeen.IsZero() {
		rec.Score = DecayScore(rec.Score, rec.LastSeen, now, e.halfLife)
	}

	// Logistic accumulation: score approaches 100 asymptotically.
	weight := weightFor(reason)
	rec.Score += trust * weight * (1 - rec.Score/100)
	if rec.Score > 100 {
		rec.Score = 100
	}

	// Corroboration: count distinct reporters.
	if !containsString(rec.ReporterIDs, reporterID) {
		rec.ReporterIDs = append(rec.ReporterIDs, reporterID)
		rec.Corroboration = len(rec.ReporterIDs)
	}

	// Update metadata.
	rec.LastSeen = now
	if rec.FirstSeen.IsZero() {
		rec.FirstSeen = now
	}
	if !containsString(rec.Reasons, reason) {
		rec.Reasons = append(rec.Reasons, reason)
	}

	ttl := 3 * e.halfLife
	if err := e.store.PutScore(ip, rec, ttl); err != nil {
		return 0, fmt.Errorf("reputation: put %q: %w", ip, err)
	}
	return rec.Score, nil
}

// Decay reads ip's current score, applies time decay, persists it, and returns the result.
// Returns 0 and nil if ip is not in the store.
func (e *Engine) Decay(ip string) (float64, error) {
	rec, err := e.store.GetScore(ip)
	if err != nil {
		return 0, fmt.Errorf("reputation: get %q: %w", ip, err)
	}
	if rec.LastSeen.IsZero() {
		return 0, nil
	}
	rec.Score = DecayScore(rec.Score, rec.LastSeen, time.Now(), e.halfLife)
	ttl := 3 * e.halfLife
	if err := e.store.PutScore(ip, rec, ttl); err != nil {
		return 0, fmt.Errorf("reputation: put %q: %w", ip, err)
	}
	return rec.Score, nil
}

// GetRecord returns the raw ScoreRecord for ip (zero value if not found).
func (e *Engine) GetRecord(ip string) (store.ScoreRecord, error) {
	return e.store.GetScore(ip)
}
```

- [ ] **Step 5: Run tests — expect PASS**

```bash
go test ./internal/reputation/...
```

Expected: `ok github.com/JoeRu/swarmguard/internal/reputation`

- [ ] **Step 6: Commit**

```bash
git add internal/reputation/
git update-index --chmod=-x internal/reputation/engine.go internal/reputation/corroboration.go internal/reputation/corroboration_test.go
git commit -m "feat(reputation): engine with logistic accumulation and corroboration tracking (spec §4.2, §4.3)"
```

---

### Task 5: Enforce Interface + NeverBlock

**Files:**
- Modify: `internal/enforce/plugin.go`
- Modify: `internal/enforce/neverblock.go`
- Create: `internal/enforce/neverblock_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/enforce/neverblock_test.go`:

```go
package enforce_test

import (
	"testing"

	"github.com/JoeRu/swarmguard/internal/enforce"
)

func TestNeverBlockRFC1918(t *testing.T) {
	nbl := enforce.NewNeverBlockList(nil)
	for _, ip := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1"} {
		if !nbl.Contains(ip) {
			t.Errorf("expected %s to be neverblock", ip)
		}
	}
}

func TestNeverBlockPublicIP(t *testing.T) {
	nbl := enforce.NewNeverBlockList(nil)
	if nbl.Contains("198.51.100.1") {
		t.Error("198.51.100.1 should not be in neverblock")
	}
}

func TestNeverBlockExtraWhitelist(t *testing.T) {
	nbl := enforce.NewNeverBlockList([]string{"203.0.113.0/24"})
	if !nbl.Contains("203.0.113.5") {
		t.Error("203.0.113.5 should be in extra whitelist")
	}
	if nbl.Contains("203.0.114.1") {
		t.Error("203.0.114.1 should not be in extra whitelist")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/enforce/...
```

Expected: compile error — `enforce.NewNeverBlockList` undefined.

- [ ] **Step 3: Update the Sink interface**

Replace `internal/enforce/plugin.go`:

```go
package enforce

import "context"

// Sink applies block decisions to a firewall backend.
// Implementations must be safe for concurrent use.
type Sink interface {
	Name() string
	// Start creates the required firewall structures (idempotent). Must be called before Block/Unblock.
	Start(ctx context.Context) error
	// Block adds ip to the deny set.
	Block(ip string) error
	// Unblock removes ip from the deny set.
	Unblock(ip string) error
	// Close releases any resources held by the backend (does NOT flush the deny set).
	Close() error
}
```

- [ ] **Step 4: Implement neverblock.go**

Replace `internal/enforce/neverblock.go`:

```go
package enforce

import (
	"fmt"
	"net"
)

// defaultNeverBlock contains CIDRs that must never be blocked (spec §6.2, invariant 3).
var defaultNeverBlock = []string{
	"127.0.0.0/8",    // loopback
	"::1/128",        // IPv6 loopback
	"10.0.0.0/8",     // RFC1918
	"172.16.0.0/12",  // RFC1918
	"192.168.0.0/16", // RFC1918
	"100.64.0.0/10",  // CGNAT (RFC6598)
	"169.254.0.0/16", // link-local
	"224.0.0.0/4",    // multicast
	"fc00::/7",       // IPv6 ULA
	"fe80::/10",      // IPv6 link-local
}

// NeverBlockList is an immutable set of CIDRs that must never be blocked.
type NeverBlockList struct {
	nets []*net.IPNet
}

// NewNeverBlockList builds a NeverBlockList from the default RFC1918 ranges plus any
// operator-provided extra CIDRs. Invalid entries in extra are silently skipped.
func NewNeverBlockList(extra []string) *NeverBlockList {
	all := append(defaultNeverBlock, extra...)
	var nets []*net.IPNet
	for _, cidr := range all {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		nets = append(nets, n)
	}
	return &NeverBlockList{nets: nets}
}

// Contains returns true if ip is covered by any CIDR in the list.
func (l *NeverBlockList) Contains(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range l.nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Assert is a no-op compile-time guard used in tests.
var _ = fmt.Sprintf
```

- [ ] **Step 5: Fix stubs that declare types (crowdsec enforce stub)**

The existing `internal/enforce/crowdsec.go` is just `package enforce`. No type implements the old `Sink`, so no compile error. Verify:

```bash
go build ./...
```

Expected: success. If it fails because another file references `Apply`, fix by removing the reference.

- [ ] **Step 6: Run tests — expect PASS**

```bash
go test ./internal/enforce/...
```

Expected: `ok github.com/JoeRu/swarmguard/internal/enforce`

- [ ] **Step 7: Commit**

```bash
git add internal/enforce/
git update-index --chmod=-x internal/enforce/plugin.go internal/enforce/neverblock.go internal/enforce/neverblock_test.go
git commit -m "feat(enforce): update Sink interface (Block/Unblock) + RFC1918 neverblock list (spec §6.2)"
```

---

### Task 6: ipset Backend

**Files:**
- Modify: `internal/enforce/ipset.go`

Note: This backend shells out to `/sbin/ipset` and `/sbin/iptables`. No unit tests that invoke real commands — those run inside Docker containers via the smoke test.

- [ ] **Step 1: Implement ipset.go**

Replace `internal/enforce/ipset.go`:

```go
package enforce

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"
)

// IpsetSink enforces blocks via ipset + iptables. Shells out to /sbin/ipset
// and /sbin/iptables — no CGo, auditable. Requires root.
type IpsetSink struct {
	setName string
	chain   string
}

// NewIpset creates an IpsetSink. setName is the ipset name; chain is the
// iptables chain (DOCKER-USER recommended for Docker environments; INPUT for host-only).
func NewIpset(setName, chain string) *IpsetSink {
	if setName == "" {
		setName = "swarmguard"
	}
	if chain == "" {
		chain = "DOCKER-USER"
	}
	return &IpsetSink{setName: setName, chain: chain}
}

func (s *IpsetSink) Name() string { return "ipset" }

// Start creates the ipset and installs the iptables rule (both idempotent).
// Logs a warning if chain is INPUT, as that misses Docker container traffic.
func (s *IpsetSink) Start(ctx context.Context) error {
	if s.chain == "INPUT" {
		log.Printf("WARN enforce/ipset: chain=INPUT will not block traffic to Docker containers; use chain=DOCKER-USER for Docker environments")
	}

	if err := s.run(ctx, "ipset", "create", s.setName, "hash:ip", "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: create set %q: %w", s.setName, err)
	}

	// Check if rule already exists before inserting.
	check := s.run(ctx, "iptables", "-C", s.chain, "-m", "set", "--match-set", s.setName, "src", "-j", "DROP")
	if check != nil {
		// Rule not present — insert at top.
		if err := s.run(ctx, "iptables", "-I", s.chain, "-m", "set", "--match-set", s.setName, "src", "-j", "DROP"); err != nil {
			return fmt.Errorf("enforce/ipset: install iptables rule: %w", err)
		}
	}
	return nil
}

// Block adds ip to the ipset.
func (s *IpsetSink) Block(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.run(ctx, "ipset", "add", s.setName, ip, "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: block %s: %w", ip, err)
	}
	return nil
}

// Unblock removes ip from the ipset.
func (s *IpsetSink) Unblock(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.run(ctx, "ipset", "del", s.setName, ip, "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: unblock %s: %w", ip, err)
	}
	return nil
}

// Close is a no-op: the set persists across daemon restarts so blocks survive.
func (s *IpsetSink) Close() error { return nil }

func (s *IpsetSink) run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

// Compile-time interface check.
var _ Sink = (*IpsetSink)(nil)
```

- [ ] **Step 2: Build to verify compilation**

```bash
go build ./internal/enforce/...
```

Expected: success.

- [ ] **Step 3: Commit**

```bash
git add internal/enforce/ipset.go
git update-index --chmod=-x internal/enforce/ipset.go
git commit -m "feat(enforce/ipset): implement ipset backend with configurable chain (spec §11.3)"
```

---

### Task 7: nftables Backend

**Files:**
- Modify: `internal/enforce/nftables.go`

- [ ] **Step 1: Implement nftables.go**

Replace `internal/enforce/nftables.go`:

```go
package enforce

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"
)

const nftTable = "swarmguard"
const nftSetName = "blocked"

// NftablesSink enforces blocks via nftables. Shells out to /sbin/nft. Requires root.
type NftablesSink struct {
	setName string
	hook    string // "input" (host traffic) or "forward" (Docker/routed)
}

// NewNftables creates a NftablesSink. hook should be "forward" in Docker environments.
func NewNftables(setName, hook string) *NftablesSink {
	if setName == "" {
		setName = nftSetName
	}
	if hook == "" {
		hook = "input"
	}
	return &NftablesSink{setName: setName, hook: hook}
}

func (s *NftablesSink) Name() string { return "nftables" }

// Start creates the nftables table, set, chain, and drop rule (all idempotent via || true).
func (s *NftablesSink) Start(ctx context.Context) error {
	if s.hook == "input" {
		log.Printf("INFO enforce/nftables: hook=input covers host traffic only; use hook=forward for Docker environments")
	}

	cmds := [][]string{
		{"nft", "add", "table", "inet", nftTable},
		{"nft", "add", "set", "inet", nftTable, s.setName, "{ type ipv4_addr; flags interval; }"},
		{"nft", "add", "chain", "inet", nftTable, s.hook, fmt.Sprintf("{ type filter hook %s priority 0; }", s.hook)},
		{"nft", "add", "rule", "inet", nftTable, s.hook, "ip", "saddr", "@" + s.setName, "drop"},
	}
	for _, args := range cmds {
		// Idempotent: ignore "already exists" errors.
		_ = exec.CommandContext(ctx, args[0], args[1:]...).Run()
	}
	return nil
}

// Block adds ip to the nftables set.
func (s *NftablesSink) Block(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "nft", "add", "element", "inet", nftTable, s.setName, "{", ip, "}").Run(); err != nil {
		return fmt.Errorf("enforce/nftables: block %s: %w", ip, err)
	}
	return nil
}

// Unblock removes ip from the nftables set.
func (s *NftablesSink) Unblock(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "nft", "delete", "element", "inet", nftTable, s.setName, "{", ip, "}").Run(); err != nil {
		return fmt.Errorf("enforce/nftables: unblock %s: %w", ip, err)
	}
	return nil
}

// Close is a no-op: the nftables rules persist across daemon restarts.
func (s *NftablesSink) Close() error { return nil }

// Compile-time interface check.
var _ Sink = (*NftablesSink)(nil)
```

- [ ] **Step 2: Build to verify compilation**

```bash
go build ./internal/enforce/...
```

Expected: success.

- [ ] **Step 3: Commit**

```bash
git add internal/enforce/nftables.go
git update-index --chmod=-x internal/enforce/nftables.go
git commit -m "feat(enforce/nftables): implement nftables backend with configurable hook"
```

---

### Task 8: Cowrie Honeypot Ingest

**Files:**
- Modify: `internal/ingest/honeypot.go`
- Create: `internal/ingest/honeypot_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/ingest/honeypot_test.go`:

```go
package ingest_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/ingest"
)

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

func TestHoneypotParsesLoginFailed(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cowrie.json")

	cfg := config.HoneypotConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	h := ingest.NewHoneypot(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := h.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		`{"eventid":"cowrie.login.failed","src_ip":"198.51.100.1","timestamp":"2026-06-10T10:00:00Z"}`,
	})

	select {
	case e := <-ch:
		if e.IP != "198.51.100.1" {
			t.Errorf("IP: got %q, want 198.51.100.1", e.IP)
		}
		if e.Reason != "ssh-auth-bruteforce" {
			t.Errorf("Reason: got %q, want ssh-auth-bruteforce", e.Reason)
		}
		if e.ReporterID != "selfpeer" {
			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestHoneypotSkipsEmptyIP(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cowrie.json")

	cfg := config.HoneypotConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	h := ingest.NewHoneypot(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch, err := h.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		`{"eventid":"cowrie.login.failed","src_ip":"","timestamp":"2026-06-10T10:00:00Z"}`,
	})

	select {
	case e := <-ch:
		t.Errorf("expected no event for empty IP, got %+v", e)
	case <-ctx.Done():
		// correct — no event emitted
	}
}

func TestHoneypotUnknownEventID(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cowrie.json")

	cfg := config.HoneypotConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	h := ingest.NewHoneypot(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := h.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		`{"eventid":"cowrie.some.new.event","src_ip":"203.0.113.5","timestamp":"2026-06-10T10:00:00Z"}`,
	})

	select {
	case e := <-ch:
		if e.Reason != "ssh-unknown" {
			t.Errorf("expected ssh-unknown for unknown eventid, got %q", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/ingest/...
```

Expected: compile error — `ingest.NewHoneypot` undefined.

- [ ] **Step 3: Implement honeypot.go**

Replace `internal/ingest/honeypot.go`:

```go
package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// cowrieEvent is one JSON line from cowrie.json.
type cowrieEvent struct {
	EventID   string `json:"eventid"`
	SrcIP     string `json:"src_ip"`
	Timestamp string `json:"timestamp"`
}

// cowrieReasons maps Cowrie eventid to SwarmGuard reason strings.
var cowrieReasons = map[string]string{
	"cowrie.login.success":  "ssh-auth-success",
	"cowrie.login.failed":   "ssh-auth-bruteforce",
	"cowrie.command.input":  "ssh-post-auth-command",
	"cowrie.session.connect": "ssh-probe",
}

// Honeypot tails a Cowrie JSONL log and emits proto.Events.
// All events carry Trust=1.0 (ground-truth anchor, spec §4.1).
type Honeypot struct {
	cfg      config.HoneypotConfig
	selfID   string
}

// NewHoneypot creates a Honeypot adapter. selfID is the local node's peer ID,
// used as ReporterID so peers can track corroboration.
func NewHoneypot(cfg config.HoneypotConfig, selfID string) *Honeypot {
	return &Honeypot{cfg: cfg, selfID: selfID}
}

func (h *Honeypot) Name() string { return "cowrie" }

// Start begins tailing the Cowrie log file and emitting events until ctx is cancelled.
func (h *Honeypot) Start(ctx context.Context) (<-chan proto.Event, error) {
	ch := make(chan proto.Event, 64)
	go h.tail(ctx, ch)
	return ch, nil
}

func (h *Honeypot) tail(ctx context.Context, ch chan<- proto.Event) {
	defer close(ch)

	pollInterval := h.cfg.PollInterval.Duration
	if pollInterval <= 0 {
		pollInterval = time.Second
	}

	var offset int64
	var lastSize int64

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f, err := os.Open(h.cfg.LogFile)
			if err != nil {
				continue // file not yet created — wait
			}

			fi, err := f.Stat()
			if err != nil {
				f.Close()
				continue
			}

			// Log rotation: file shrank — reopen from start.
			if fi.Size() < lastSize {
				offset = 0
			}
			lastSize = fi.Size()

			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				f.Close()
				continue
			}

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Bytes()
				offset += int64(len(line)) + 1 // +1 for newline

				var ce cowrieEvent
				if err := json.Unmarshal(line, &ce); err != nil {
					continue
				}
				if ce.SrcIP == "" {
					continue
				}

				reason, ok := cowrieReasons[ce.EventID]
				if !ok {
					reason = "ssh-unknown"
				}

				e := proto.Event{
					IP:         ce.SrcIP,
					Reason:     reason,
					Timestamp:  time.Now(),
					ReporterID: h.selfID,
				}

				select {
				case ch <- e:
				case <-ctx.Done():
					f.Close()
					return
				default:
					// Channel full — drop (high-volume honeypot noise).
					log.Printf("ingest/cowrie: channel full, dropping event for %s", ce.SrcIP)
				}
			}
			f.Close()
		}
	}
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test ./internal/ingest/...
```

Expected: `ok github.com/JoeRu/swarmguard/internal/ingest`

- [ ] **Step 5: Commit**

```bash
git add internal/ingest/honeypot.go internal/ingest/honeypot_test.go
git update-index --chmod=-x internal/ingest/honeypot.go internal/ingest/honeypot_test.go
git commit -m "feat(ingest/cowrie): implement Cowrie JSONL tail adapter (spec §4.1)"
```

---

### Task 9: Node Composition Root

**Files:**
- Create: `internal/node/node.go`

- [ ] **Step 1: Implement node.go**

Create `internal/node/node.go`:

```go
package node

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/enforce"
	"github.com/JoeRu/swarmguard/internal/ingest"
	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/internal/transport"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// Node is the composition root that connects ingest, reputation, enforce, and transport.
type Node struct {
	cfg        *config.Config
	transport  *transport.Node // may be nil (solo mode without bootstrap)
	store      *store.BadgerStore
	rep        *reputation.Engine
	sources    []ingest.Source
	sink       enforce.Sink
	neverblock *enforce.NeverBlockList
	selfID     string
}

// New wires all subsystems from cfg. transport may be nil for local-only operation.
func New(cfg *config.Config, t *transport.Node) (*Node, error) {
	s, err := store.Open(cfg.Store.Dir)
	if err != nil {
		return nil, fmt.Errorf("node: open store: %w", err)
	}

	halfLife := cfg.Reputation.HalfLife.Duration
	if halfLife <= 0 {
		halfLife = 7 * 24 * time.Hour
	}
	eng := reputation.New(s, halfLife)

	var sink enforce.Sink
	switch cfg.Enforce.Backend {
	case "nftables":
		sink = enforce.NewNftables(cfg.Enforce.SetName, cfg.Enforce.NftHook)
	default:
		sink = enforce.NewIpset(cfg.Enforce.SetName, cfg.Enforce.Chain)
	}

	nbl := enforce.NewNeverBlockList(cfg.Enforce.ExtraWhitelist)

	var sources []ingest.Source
	if cfg.Ingest.Honeypot.Enabled {
		selfID := ""
		if t != nil {
			selfID = t.Host().ID().String()
		}
		sources = append(sources, ingest.NewHoneypot(cfg.Ingest.Honeypot, selfID))
	}

	selfID := ""
	if t != nil {
		selfID = t.Host().ID().String()
	}

	return &Node{
		cfg:        cfg,
		transport:  t,
		store:      s,
		rep:        eng,
		sources:    sources,
		sink:       sink,
		neverblock: nbl,
		selfID:     selfID,
	}, nil
}

// Run starts all subsystems and blocks until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	if err := n.sink.Start(ctx); err != nil {
		return fmt.Errorf("node: start enforce sink: %w", err)
	}
	defer n.sink.Close()
	defer n.store.Close()

	var ingestChans []<-chan proto.Event
	for _, src := range n.sources {
		ch, err := src.Start(ctx)
		if err != nil {
			return fmt.Errorf("node: start source %s: %w", src.Name(), err)
		}
		ingestChans = append(ingestChans, ch)
	}
	localEvents := fanIn(ctx, ingestChans...)

	decayInterval := n.cfg.Reputation.DecayInterval.Duration
	if decayInterval <= 0 {
		decayInterval = time.Hour
	}
	ticker := time.NewTicker(decayInterval)
	defer ticker.Stop()

	var remoteCh <-chan proto.Event
	if n.transport != nil {
		remoteCh = n.transport.Subscribe()
	}

	for {
		select {
		case e, ok := <-localEvents:
			if !ok {
				localEvents = nil
				continue
			}
			n.processLocal(ctx, e)
		case e, ok := <-remoteCh:
			if !ok {
				remoteCh = nil
				continue
			}
			n.processRemote(e)
		case <-ticker.C:
			n.runDecay()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (n *Node) processLocal(ctx context.Context, e proto.Event) {
	if n.neverblock.Contains(e.IP) {
		return
	}
	e.ReporterID = n.selfID
	score, err := n.rep.Record(e.IP, e.Reason, n.selfID, 1.0)
	if err != nil {
		log.Printf("node: record local %s: %v", e.IP, err)
		return
	}
	if score >= n.cfg.Reputation.BlockThreshold {
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		}
	}
	if n.transport != nil {
		if err := n.transport.Publish(ctx, e); err != nil {
			log.Printf("node: publish %s: %v", e.IP, err)
		}
	}
}

func (n *Node) processRemote(e proto.Event) {
	if n.neverblock.Contains(e.IP) {
		return
	}
	score, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, 0.3)
	if err != nil {
		log.Printf("node: record remote %s: %v", e.IP, err)
		return
	}
	if score >= n.cfg.Reputation.BlockThreshold {
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		}
	}
}

func (n *Node) runDecay() {
	err := n.store.ScanScores(func(ip string, _ store.ScoreRecord) error {
		score, err := n.rep.Decay(ip)
		if err != nil {
			log.Printf("node: decay %s: %v", ip, err)
			return nil
		}
		if score < n.cfg.Reputation.UnblockThreshold {
			if err := n.sink.Unblock(ip); err != nil {
				log.Printf("node: unblock %s: %v", ip, err)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("node: decay scan: %v", err)
	}
}

// fanIn merges multiple event channels into one.
func fanIn(ctx context.Context, chans ...<-chan proto.Event) <-chan proto.Event {
	out := make(chan proto.Event, 64)
	var wg sync.WaitGroup
	for _, ch := range chans {
		wg.Add(1)
		go func(c <-chan proto.Event) {
			defer wg.Done()
			for {
				select {
				case e, ok := <-c:
					if !ok {
						return
					}
					select {
					case out <- e:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}(ch)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
```

- [ ] **Step 2: Build to verify**

```bash
go build ./...
```

Expected: success.

- [ ] **Step 3: Commit**

```bash
git add internal/node/node.go
git update-index --chmod=-x internal/node/node.go
git commit -m "feat(node): composition root wiring ingest→reputation→enforce + gossip integration"
```

---

### Task 10: swarmd Config-Driven Wiring

**Files:**
- Modify: `cmd/swarmd/main.go`

- [ ] **Step 1: Update main.go**

Replace `cmd/swarmd/main.go`:

```go
// Command swarmd is the long-running SwarmGuard P2P node daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"strings"
	"syscall"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/node"
	"github.com/JoeRu/swarmguard/internal/transport"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file (optional; flags override)")
	listen    := flag.String("listen", "/ip4/0.0.0.0/tcp/7700", "multiaddr to listen on")
	advertise := flag.String("advertise", "", "multiaddr to print as the public address (for Docker/NAT)")
	bootstrap := flag.String("bootstrap", "", "comma-separated bootstrap peer multiaddrs (must include /p2p/<peerID>)")
	relay     := flag.Bool("relay", false, "run as relay/aggregator node (does not process local events)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := config.Defaults()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("load config %q: %v", *configPath, err)
		}
		cfg = loaded
	}

	listenMA, err := multiaddr.NewMultiaddr(*listen)
	if err != nil {
		log.Fatalf("--listen %q: %v", *listen, err)
	}

	mode := transport.ModeLeaf
	if *relay {
		mode = transport.ModeRelay
	}

	t, err := transport.New(ctx, transport.Options{
		ListenAddrs: []multiaddr.Multiaddr{listenMA},
		Mode:        mode,
	})
	if err != nil {
		log.Fatalf("start transport: %v", err)
	}
	defer t.Close()

	fmt.Printf("peer ID: %s\n", t.Host().ID())
	if *advertise != "" {
		fmt.Printf("listening on: %s/p2p/%s\n", *advertise, t.Host().ID())
	} else {
		for _, addr := range t.Host().Addrs() {
			fmt.Printf("listening on: %s/p2p/%s\n", addr, t.Host().ID())
		}
	}

	if *bootstrap != "" {
		var peers []peer.AddrInfo
		for _, raw := range strings.Split(*bootstrap, ",") {
			raw = strings.TrimSpace(raw)
			ma, err := multiaddr.NewMultiaddr(raw)
			if err != nil {
				log.Fatalf("invalid bootstrap addr %q: %v", raw, err)
			}
			ai, err := peer.AddrInfoFromP2pAddr(ma)
			if err != nil {
				log.Fatalf("parse bootstrap peer %q: %v", raw, err)
			}
			peers = append(peers, *ai)
		}
		if err := t.Bootstrap(ctx, peers); err != nil {
			log.Printf("bootstrap warning: %v", err)
		}
	}

	if *relay {
		log.Println("running as relay/aggregator — waiting for connections")
		<-ctx.Done()
		return
	}

	n, err := node.New(cfg, t)
	if err != nil {
		log.Fatalf("create node: %v", err)
	}

	log.Printf("swarmd running (enforce=%s, honeypot=%v)",
		cfg.Enforce.Backend, cfg.Ingest.Honeypot.Enabled)

	if err := n.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("node exited: %v", err)
	}
}
```

- [ ] **Step 2: Build to verify**

```bash
go build ./cmd/swarmd/...
```

Expected: success.

- [ ] **Step 3: Smoke check — node starts without config file**

```bash
./bin/swarmd --listen /ip4/127.0.0.1/tcp/17700 &
SWARMD_PID=$!
sleep 2
kill $SWARMD_PID 2>/dev/null || true
```

Expected: prints `peer ID: 12D3...` and exits cleanly on SIGTERM. No panic.

- [ ] **Step 4: Commit**

```bash
git add cmd/swarmd/main.go
git update-index --chmod=-x cmd/swarmd/main.go
git commit -m "feat(swarmd): wire node composition root; add --config flag for YAML config"
```

---

### Task 11: Integration — Reputation Store

**Files:**
- Create: `test/integration/reputation_store_test.go`

- [ ] **Step 1: Write the test**

Create `test/integration/reputation_store_test.go`:

```go
package integration_test

import (
	"math"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
)

func openEngine(t *testing.T, halfLife time.Duration) *reputation.Engine {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return reputation.New(s, halfLife)
}

func TestEngineRecordAndGetScore(t *testing.T) {
	e := openEngine(t, 7*24*time.Hour)
	score, err := e.Record("1.2.3.4", "ssh-auth-success", "peer1", 1.0)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if score <= 0 {
		t.Errorf("expected positive score, got %v", score)
	}
	rec, err := e.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if math.Abs(rec.Score-score) > 0.001 {
		t.Errorf("persisted score %v != returned score %v", rec.Score, score)
	}
}

func TestEngineDecayReducesScore(t *testing.T) {
	// Use 1ms half-life so score decays to near-zero very quickly.
	e := openEngine(t, time.Millisecond)

	_, err := e.Record("5.6.7.8", "ssh-probe", "peer1", 1.0)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	decayed, err := e.Decay("5.6.7.8")
	if err != nil {
		t.Fatalf("Decay: %v", err)
	}
	if decayed > 1 {
		t.Errorf("expected near-zero after decay, got %v", decayed)
	}
}

func TestEngineMultipleReportersCorroboration(t *testing.T) {
	e := openEngine(t, 7*24*time.Hour)
	for i, peer := range []string{"p1", "p2", "p3"} {
		_, err := e.Record("9.9.9.9", "ssh-probe", peer, 0.3)
		if err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	rec, err := e.GetRecord("9.9.9.9")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Corroboration != 3 {
		t.Errorf("expected corroboration=3, got %d", rec.Corroboration)
	}
}
```

- [ ] **Step 2: Run to verify PASS**

```bash
go test ./test/integration/...
```

Expected: `ok github.com/JoeRu/swarmguard/test/integration`

- [ ] **Step 3: Commit**

```bash
git add test/integration/reputation_store_test.go
git update-index --chmod=-x test/integration/reputation_store_test.go
git commit -m "test(integration): reputation engine + store round-trip tests"
```

---

### Task 12: Integration — Full Pipeline

**Files:**
- Create: `test/integration/pipeline_test.go`

- [ ] **Step 1: Write the test**

Create `test/integration/pipeline_test.go`:

```go
package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/enforce"
	"github.com/JoeRu/swarmguard/internal/ingest"
	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
)

// mockSink records Block/Unblock calls for assertions.
type mockSink struct {
	mu      sync.Mutex
	blocked map[string]bool
}

func newMockSink() *mockSink { return &mockSink{blocked: map[string]bool{}} }
func (m *mockSink) Name() string                        { return "mock" }
func (m *mockSink) Start(_ context.Context) error       { return nil }
func (m *mockSink) Close() error                        { return nil }
func (m *mockSink) Block(ip string) error               { m.mu.Lock(); m.blocked[ip] = true; m.mu.Unlock(); return nil }
func (m *mockSink) Unblock(ip string) error             { m.mu.Lock(); delete(m.blocked, ip); m.mu.Unlock(); return nil }
func (m *mockSink) IsBlocked(ip string) bool            { m.mu.Lock(); defer m.mu.Unlock(); return m.blocked[ip] }

var _ enforce.Sink = (*mockSink)(nil)

func writeCowrieLine(t *testing.T, path, eventid, ip string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	line := `{"eventid":"` + eventid + `","src_ip":"` + ip + `","timestamp":"2026-06-10T10:00:00Z"}` + "\n"
	if _, err := f.WriteString(line); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestPipelineBlocksAfterThreshold(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cowrie.json")

	s, err := store.Open(dir + "/db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	// Use short half-life so scores don't decay in test time.
	eng := reputation.New(s, 24*time.Hour)
	sink := newMockSink()
	nbl := enforce.NewNeverBlockList(nil)

	cfg := config.HoneypotConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 30 * time.Millisecond},
	}
	honeypot := ingest.NewHoneypot(cfg, "self")

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	ch, err := honeypot.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	const blockThreshold = 75.0
	const targetIP = "203.0.113.99"

	// Write two ssh-auth-success (weight=40 each).
	// First: score = 1.0 × 40 × (1 - 0/100) = 40
	// Second: score += 1.0 × 40 × (1 - 40/100) = 40 + 24 = 64
	// Third: score += 1.0 × 40 × (1 - 64/100) = 64 + 14.4 = 78.4 → exceeds 75
	go func() {
		time.Sleep(50 * time.Millisecond)
		for i := 0; i < 3; i++ {
			writeCowrieLine(t, logPath, "cowrie.login.success", targetIP)
			time.Sleep(60 * time.Millisecond)
		}
	}()

	blocked := false
	for !blocked {
		select {
		case e, ok := <-ch:
			if !ok {
				goto done
			}
			if nbl.Contains(e.IP) {
				continue
			}
			score, err := eng.Record(e.IP, e.Reason, e.ReporterID, 1.0)
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			if score >= blockThreshold {
				if err := sink.Block(e.IP); err != nil {
					t.Fatalf("Block: %v", err)
				}
				blocked = true
			}
		case <-ctx.Done():
			goto done
		}
	}
done:
	if !sink.IsBlocked(targetIP) {
		t.Errorf("expected %s to be blocked after threshold crossed", targetIP)
	}
}

func TestPipelineNeverBlockSkipped(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cowrie.json")

	s, err := store.Open(dir + "/db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	eng := reputation.New(s, 24*time.Hour)
	sink := newMockSink()
	nbl := enforce.NewNeverBlockList(nil)

	cfg := config.HoneypotConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 30 * time.Millisecond},
	}
	honeypot := ingest.NewHoneypot(cfg, "self")

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	ch, err := honeypot.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	const neverBlockIP = "192.168.1.1"

	go func() {
		for i := 0; i < 10; i++ {
			writeCowrieLine(t, logPath, "cowrie.login.success", neverBlockIP)
			time.Sleep(20 * time.Millisecond)
		}
	}()

	for {
		select {
		case e, ok := <-ch:
			if !ok {
				goto done
			}
			if nbl.Contains(e.IP) {
				continue
			}
			score, _ := eng.Record(e.IP, e.Reason, e.ReporterID, 1.0)
			if score >= 75 {
				_ = sink.Block(e.IP)
			}
		case <-ctx.Done():
			goto done
		}
	}
done:
	if sink.IsBlocked(neverBlockIP) {
		t.Errorf("neverblock IP %s must never be blocked", neverBlockIP)
	}
}
```

- [ ] **Step 2: Run to verify PASS**

```bash
go test ./test/integration/...
```

Expected: `ok github.com/JoeRu/swarmguard/test/integration`

- [ ] **Step 3: Commit**

```bash
git add test/integration/pipeline_test.go
git update-index --chmod=-x test/integration/pipeline_test.go
git commit -m "test(integration): full pipeline test with mock sink and neverblock verification"
```

---

### Task 13: Adversarial — Sybil Flood

**Files:**
- Create: `test/adversarial/sybil_ingest_test.go`

- [ ] **Step 1: Create the adversarial directory and write the test**

```bash
mkdir -p /mnt/c/Users/johan/code/swarmguard/test/adversarial
```

Create `test/adversarial/sybil_ingest_test.go`:

```go
// Package adversarial tests poisoning and sybil scenarios (spec §4.2, §4.3).
// This suite is a CI gate: run with "make adversarial".
package adversarial_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
)

func openEngine(t *testing.T) *reputation.Engine {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return reputation.New(s, 7*24*time.Hour)
}

// TestSybilFloodScoreCapped asserts that 50 distinct peers all reporting the
// same IP cannot push the score past 100, regardless of report count.
func TestSybilFloodScoreCapped(t *testing.T) {
	e := openEngine(t)
	const targetIP = "1.2.3.4"
	const numPeers = 50

	var lastScore float64
	for i := 0; i < numPeers; i++ {
		peerID := fmt.Sprintf("sybil-peer-%d", i)
		for j := 0; j < 10; j++ {
			score, err := e.Record(targetIP, "ssh-auth-success", peerID, 0.3)
			if err != nil {
				t.Fatalf("peer %d report %d: %v", i, j, err)
			}
			if score > 100 {
				t.Fatalf("score exceeded 100: %.2f (peer %d, report %d)", score, i, j)
			}
			lastScore = score
		}
	}

	if lastScore <= 0 {
		t.Error("expected non-zero score after sybil flood")
	}
	t.Logf("final score after %d peers × 10 reports: %.2f (cap=100)", numPeers, lastScore)
}

// TestSybilFloodCorroborationAccurate asserts corroboration count equals distinct reporters.
func TestSybilFloodCorroborationAccurate(t *testing.T) {
	e := openEngine(t)
	const targetIP = "5.6.7.8"
	const numPeers = 20

	for i := 0; i < numPeers; i++ {
		peerID := fmt.Sprintf("peer-%d", i)
		_, err := e.Record(targetIP, "ssh-probe", peerID, 0.3)
		if err != nil {
			t.Fatalf("peer %d: %v", i, err)
		}
	}

	rec, err := e.GetRecord(targetIP)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Corroboration != numPeers {
		t.Errorf("corroboration: got %d, want %d", rec.Corroboration, numPeers)
	}
}
```

- [ ] **Step 2: Run adversarial suite**

```bash
make adversarial
```

Expected: `ok github.com/JoeRu/swarmguard/test/adversarial`

- [ ] **Step 3: Commit**

```bash
git add test/adversarial/sybil_ingest_test.go
git update-index --chmod=-x test/adversarial/sybil_ingest_test.go
git commit -m "test(adversarial): sybil flood — score capped at 100, corroboration count accurate"
```

---

### Task 14: Adversarial — NeverBlock Poisoning

**Files:**
- Create: `test/adversarial/poisoning_test.go`

- [ ] **Step 1: Write the test**

Create `test/adversarial/poisoning_test.go`:

```go
package adversarial_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/enforce"
	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

type recordingSink struct {
	mu      sync.Mutex
	blocked map[string]bool
}

func newRecordingSink() *recordingSink { return &recordingSink{blocked: map[string]bool{}} }
func (r *recordingSink) Name() string                   { return "recording" }
func (r *recordingSink) Start(_ context.Context) error  { return nil }
func (r *recordingSink) Close() error                   { return nil }
func (r *recordingSink) Block(ip string) error          { r.mu.Lock(); r.blocked[ip] = true; r.mu.Unlock(); return nil }
func (r *recordingSink) Unblock(ip string) error        { r.mu.Lock(); delete(r.blocked, ip); r.mu.Unlock(); return nil }
func (r *recordingSink) WasBlocked(ip string) bool      { r.mu.Lock(); defer r.mu.Unlock(); return r.blocked[ip] }

var _ enforce.Sink = (*recordingSink)(nil)

// simulateRemote mimics node.processRemote: checks neverblock before recording.
func simulateRemote(
	e proto.Event,
	nbl *enforce.NeverBlockList,
	eng *reputation.Engine,
	sink *recordingSink,
	threshold float64,
) {
	if nbl.Contains(e.IP) {
		return
	}
	score, _ := eng.Record(e.IP, e.Reason, e.ReporterID, 0.3)
	if score >= threshold {
		_ = sink.Block(e.IP)
	}
}

// TestPoisonNeverBlockIP asserts that a malicious remote peer cannot cause
// a neverblock IP (e.g., 192.168.1.1) to be added to the block set,
// no matter how many times it reports it.
func TestPoisonNeverBlockIP(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	eng := reputation.New(s, 7*24*time.Hour)
	sink := newRecordingSink()
	nbl := enforce.NewNeverBlockList(nil)

	const poisonIP = "10.0.0.1"
	const numReports = 200

	for i := 0; i < numReports; i++ {
		simulateRemote(proto.Event{
			IP:         poisonIP,
			Reason:     "ssh-auth-success",
			ReporterID: "attacker",
			Timestamp:  time.Now(),
		}, nbl, eng, sink, 75.0)
	}

	if sink.WasBlocked(poisonIP) {
		t.Errorf("neverblock IP %s was blocked after %d malicious reports", poisonIP, numReports)
	}

	// Confirm the score was never written (neverblock check prevents Record call).
	rec, err := eng.GetRecord(poisonIP)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Score > 0 {
		t.Errorf("neverblock IP scored %.2f — neverblock check must happen before Record()", rec.Score)
	}
}

// TestLegitimateIPStillBlocked confirms the pipeline still blocks non-whitelisted IPs.
func TestLegitimateIPStillBlocked(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	eng := reputation.New(s, 7*24*time.Hour)
	sink := newRecordingSink()
	nbl := enforce.NewNeverBlockList(nil)

	const targetIP = "198.51.100.200"

	for i := 0; i < 5; i++ {
		simulateRemote(proto.Event{
			IP:         targetIP,
			Reason:     "ssh-auth-success",
			ReporterID: "honest-peer",
			Timestamp:  time.Now(),
		}, nbl, eng, sink, 75.0)
	}

	if !sink.WasBlocked(targetIP) {
		t.Errorf("expected %s to be blocked after repeated honest reports", targetIP)
	}
}
```

- [ ] **Step 2: Run adversarial suite**

```bash
make adversarial
```

Expected: `ok github.com/JoeRu/swarmguard/test/adversarial`

- [ ] **Step 3: Run full test suite**

```bash
make test
```

Expected: all packages pass.

- [ ] **Step 4: Commit**

```bash
git add test/adversarial/poisoning_test.go
git update-index --chmod=-x test/adversarial/poisoning_test.go
git commit -m "test(adversarial): neverblock poisoning prevention (spec §6.2, invariant 3)"
```

---

## Self-Review

**Spec coverage:**
- §4.1 Ground-truth anchor: Task 8 (Cowrie trust=1.0) ✓
- §4.2 Corroboration: Task 4 (Engine.Record, distinct reporters) + Task 13 ✓
- §4.3 Asymmetric decay: Task 3 (DecayScore) ✓
- §6.2 Local-only whitelist: Task 5 (NeverBlockList) + Task 14 ✓
- §7.2 ScoreEntry persisted: Task 2 (store.ScoreRecord in BadgerDB) ✓
- §8 Score dynamics: Task 4 (logistic accumulation) ✓
- §9 GDPR/TTL: Task 4 (TTL = 3×halfLife in PutScore) ✓
- §11.3 O(1) enforcement: Tasks 6+7 (ipset hash:ip / nftables set) ✓
- Docker DOCKER-USER chain: Tasks 6+7 (default chain + warning) ✓
- Config-driven backend selection: Tasks 1+9+10 ✓
- Real-life Cowrie validation: documented in spec Phase 2; not in this plan (depends on operator machine) ✓

**No TBDs or placeholders found.**

**Type consistency check:**
- `store.ScoreRecord` defined Task 2, used consistently in Tasks 4, 9, 11, 12, 13, 14 ✓
- `reputation.Engine.Record(ip, reason, reporterID string, trust float64) (float64, error)` — consistent across Tasks 4, 9, 11, 12, 13, 14 ✓
- `reputation.DecayScore(score float64, lastSeen, now time.Time, halfLife time.Duration) float64` — consistent Tasks 3, 4 ✓
- `enforce.Sink` interface (Name/Start/Block/Unblock/Close) — consistent Tasks 5, 6, 7, 9, 12, 14 ✓
- `ingest.NewHoneypot(cfg config.HoneypotConfig, selfID string) *Honeypot` — consistent Tasks 8, 9, 12 ✓
- `config.Duration` — used in Tasks 1, 8, 9 ✓
