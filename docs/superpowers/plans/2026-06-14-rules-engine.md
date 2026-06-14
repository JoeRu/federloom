# Rules Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single `block_threshold` scalar with a hot-reloadable YAML rule file that drives all block decisions via named, composable rules evaluated against event properties, reputation score, corroboration, and burst counters.

**Architecture:** New package `internal/rules` owns `BurstStore` (in-memory sliding-window counter) and `RuleSet` (YAML-driven rule evaluator with fileStat hot-reload). `internal/config` gains `RulesFile` field and `RulesFilePath()` helper. `internal/node` replaces every `score >= blockThreshold` check with `n.rules.Evaluate(event, scoreRecord, burstStore)`. Missing rules file falls back silently to legacy threshold behaviour — zero config change required for existing deployments.

**Tech Stack:** Go 1.22, `gopkg.in/yaml.v3` (already used by `internal/config`), `sync.RWMutex`, `sync.Mutex`.

**Spec:** `docs/superpowers/specs/2026-06-14-rules-engine-design.md`

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `internal/rules/burst.go` | In-memory per-(ip,reason) sliding-window counter |
| Create | `internal/rules/burst_test.go` | Unit tests for BurstStore |
| Create | `internal/rules/rule.go` | Rule struct, RuleSet, Load(), Evaluate(), hot-reload |
| Create | `internal/rules/rule_test.go` | Unit tests for RuleSet.Evaluate() and hot-reload |
| Create | `deploy/examples/rules.yaml` | Default rules operators can copy to their data dir |
| Modify | `internal/config/config.go` | Add `RulesFile string` to `ReputationConfig`; add `RulesFilePath()` |
| Modify | `internal/node/node.go` | Add `rules`+`burst` fields; replace block-decision logic |
| Modify | `CHANGELOG.md` | Document the change |

---

## Task 1: BurstStore

**Files:**
- Create: `internal/rules/burst.go`
- Create: `internal/rules/burst_test.go`

### Context

`BurstStore` is a thread-safe, in-memory map from `(ip, reason)` → sorted slice of `time.Time`. `Record()` appends; `Count()` evicts old timestamps and returns how many remain within the window. State resets on daemon restart — burst rules fire on live floods, not cold history.

- [ ] **Step 1: Write the failing tests**

Create `internal/rules/burst_test.go`:

```go
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
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd /root/swarmguard
go test ./internal/rules/... 2>&1 | head -5
```

Expected: `cannot find package "github.com/JoeRu/swarmguard/internal/rules"` or similar compile error.

- [ ] **Step 3: Implement BurstStore**

Create `internal/rules/burst.go`:

```go
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

// Count returns how many events for (ip, reason) fall within the last window.
// Evicts stale entries as a side effect (lazy GC — no background goroutine).
func (b *BurstStore) Count(ip, reason string, window time.Duration) int {
	k := burstKey{ip, reason}
	cutoff := time.Now().Add(-window)
	b.mu.Lock()
	defer b.mu.Unlock()
	ts := b.entries[k]
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	b.entries[k] = ts[i:]
	return len(b.entries[k])
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/rules/... -v -run TestBurst
```

Expected output (all PASS):
```
--- PASS: TestBurstCount_Empty
--- PASS: TestBurstCount_WithinWindow
--- PASS: TestBurstCount_Eviction
--- PASS: TestBurstCount_DifferentReasonIsolated
```

- [ ] **Step 5: Commit**

```bash
git add internal/rules/burst.go internal/rules/burst_test.go
git commit -m "feat(rules): add BurstStore — in-memory sliding-window burst counter"
```

---

## Task 2: RuleSet

**Files:**
- Create: `internal/rules/rule.go`
- Create: `internal/rules/rule_test.go`

### Context

`RuleSet` loads a YAML file of `Rule` structs. `Evaluate()` walks rules top-to-bottom; first rule whose every present condition matches wins. Hot-reload: on each `Evaluate()` call, `maybeReload()` stats the file; if mtime+size changed, it re-reads. Parse errors keep the last-good ruleset.

`Rule.BurstWindow` must unmarshall from YAML strings like `"10m"`. Go's `time.Duration` does not implement `yaml.Unmarshaler`, so we define a local `duration` wrapper — same pattern as `config.Duration` in `internal/config/config.go`.

**Key types used from other packages:**
- `store.ScoreRecord` from `internal/store` — fields: `Score float64`, `Corroboration int`, `StrangerSeen bool`
- `proto.Event` from `pkg/proto` — fields: `IP string`, `Reason string`
- `*BurstStore` from this package (Task 1)

- [ ] **Step 1: Write the failing tests**

Create `internal/rules/rule_test.go`:

```go
package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// helpers

func noRec() store.ScoreRecord { return store.ScoreRecord{} }

func recScore(s float64) store.ScoreRecord { return store.ScoreRecord{Score: s} }

func recCorr(c int) store.ScoreRecord { return store.ScoreRecord{Corroboration: c} }

func recAnchored() store.ScoreRecord {
	return store.ScoreRecord{Corroboration: 1, StrangerSeen: false}
}

func recStranger() store.ScoreRecord {
	return store.ScoreRecord{Corroboration: 1, StrangerSeen: true}
}

func ev(reason string) proto.Event { return proto.Event{IP: "1.2.3.4", Reason: reason} }

func emptyBurst() *BurstStore { return NewBurstStore() }

// --- tests ---

func TestEvaluate_LegacyFallback_Block(t *testing.T) {
	rs := Load("", 75)
	got := rs.Evaluate(ev("ssh-probe"), recScore(80), emptyBurst())
	if got != ActionBlock {
		t.Errorf("score=80 > fallback=75: got %v, want block", got)
	}
}

func TestEvaluate_LegacyFallback_NoBlock(t *testing.T) {
	rs := Load("", 75)
	got := rs.Evaluate(ev("ssh-probe"), recScore(50), emptyBurst())
	if got != ActionNone {
		t.Errorf("score=50 < fallback=75: got %v, want none", got)
	}
}

func TestEvaluate_ReasonMatch(t *testing.T) {
	path := writeRules(t, `
- name: ssh-only
  reason: ssh-probe
  min_corroboration: 1
  action: block
`)
	rs := Load(path, 75)
	// matching reason
	if got := rs.Evaluate(ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionBlock {
		t.Errorf("matching reason: got %v, want block", got)
	}
	// non-matching reason
	if got := rs.Evaluate(ev("smtp-auth-bruteforce"), recCorr(1), emptyBurst()); got != ActionNone {
		t.Errorf("non-matching reason: got %v, want none", got)
	}
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	path := writeRules(t, `
- name: first
  reason: ssh-probe
  min_corroboration: 1
  action: watch
- name: second
  reason: ssh-probe
  min_corroboration: 1
  action: block
`)
	rs := Load(path, 75)
	got := rs.Evaluate(ev("ssh-probe"), recCorr(1), emptyBurst())
	if got != ActionWatch {
		t.Errorf("first-match-wins: got %v, want watch", got)
	}
}

func TestEvaluate_MinCorroboration(t *testing.T) {
	path := writeRules(t, `
- name: needs-3
  reason: ssh-probe
  min_corroboration: 3
  action: block
`)
	rs := Load(path, 999)
	if got := rs.Evaluate(ev("ssh-probe"), recCorr(2), emptyBurst()); got != ActionNone {
		t.Errorf("corroboration=2 < 3: got %v, want none", got)
	}
	if got := rs.Evaluate(ev("ssh-probe"), recCorr(3), emptyBurst()); got != ActionBlock {
		t.Errorf("corroboration=3 >= 3: got %v, want block", got)
	}
}

func TestEvaluate_AnchoredOnly(t *testing.T) {
	path := writeRules(t, `
- name: anchored-only
  reason: ssh-probe
  min_corroboration: 1
  anchored_only: true
  action: block
`)
	rs := Load(path, 999)
	if got := rs.Evaluate(ev("ssh-probe"), recStranger(), emptyBurst()); got != ActionNone {
		t.Errorf("stranger: got %v, want none", got)
	}
	if got := rs.Evaluate(ev("ssh-probe"), recAnchored(), emptyBurst()); got != ActionBlock {
		t.Errorf("anchored: got %v, want block", got)
	}
}

func TestEvaluate_MinBurst(t *testing.T) {
	path := writeRules(t, `
- name: burst-rule
  reason: ssh-probe
  min_burst: 3
  burst_window: 1m
  action: block
`)
	rs := Load(path, 999)
	b := NewBurstStore()
	now := time.Now()

	// 2 events — not enough
	b.Record("1.2.3.4", "ssh-probe", now)
	b.Record("1.2.3.4", "ssh-probe", now)
	if got := rs.Evaluate(ev("ssh-probe"), noRec(), b); got != ActionNone {
		t.Errorf("burst=2 < 3: got %v, want none", got)
	}

	// 3rd event — fires
	b.Record("1.2.3.4", "ssh-probe", now)
	if got := rs.Evaluate(ev("ssh-probe"), noRec(), b); got != ActionBlock {
		t.Errorf("burst=3 >= 3: got %v, want block", got)
	}
}

func TestEvaluate_HotReload(t *testing.T) {
	path := writeRules(t, `
- name: first-version
  reason: ssh-probe
  min_corroboration: 1
  action: watch
`)
	rs := Load(path, 999)
	if got := rs.Evaluate(ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionWatch {
		t.Fatalf("before reload: got %v, want watch", got)
	}

	// Overwrite the file with a different rule (sleep 1ms to ensure mtime differs
	// on systems with 1ms mtime resolution).
	time.Sleep(2 * time.Millisecond)
	writeRulesTo(t, path, `
- name: second-version
  reason: ssh-probe
  min_corroboration: 1
  action: block
`)
	if got := rs.Evaluate(ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionBlock {
		t.Errorf("after reload: got %v, want block", got)
	}
}

func TestEvaluate_CorruptFileKeepsLastGood(t *testing.T) {
	path := writeRules(t, `
- name: good-rule
  reason: ssh-probe
  min_corroboration: 1
  action: block
`)
	rs := Load(path, 999)
	// Verify good rule loaded
	if got := rs.Evaluate(ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionBlock {
		t.Fatalf("initial load: got %v, want block", got)
	}
	// Overwrite with corrupt YAML
	time.Sleep(2 * time.Millisecond)
	writeRulesTo(t, path, `:::not yaml:::`)
	// Should still use last-good ruleset
	if got := rs.Evaluate(ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionBlock {
		t.Errorf("after corrupt file: got %v, want block (last-good)", got)
	}
}

// --- helpers ---

func writeRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRulesTo(t, path, content)
	return path
}

func writeRulesTo(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write rules file: %v", err)
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/rules/... -run TestEvaluate 2>&1 | head -10
```

Expected: compile error — `Load`, `ActionBlock`, etc. not defined yet.

- [ ] **Step 3: Implement RuleSet**

Create `internal/rules/rule.go`:

```go
package rules

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// Action is the outcome of a matched rule.
type Action string

const (
	ActionBlock  Action = "block"
	ActionWatch  Action = "watch"
	ActionIgnore Action = "ignore"
	ActionNone   Action = "" // no rule matched
)

// duration wraps time.Duration to support YAML unmarshalling from strings
// like "10m", "1h". Same pattern as config.Duration.
type duration struct{ time.Duration }

func (d *duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("rules: parse duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// Rule is a single named rule. All present conditions must match (AND logic).
// The first matching rule in the list wins.
type Rule struct {
	Name             string   `yaml:"name"`
	Reason           string   `yaml:"reason"`
	MinScore         float64  `yaml:"min_score"`
	MinCorroboration int      `yaml:"min_corroboration"`
	AnchoredOnly     bool     `yaml:"anchored_only"`
	MinBurst         int      `yaml:"min_burst"`
	BurstWindow      duration `yaml:"burst_window"`
	Action           Action   `yaml:"action"`
}

type fileStat struct {
	mtime time.Time
	size  int64
}

// RuleSet holds the loaded rules and hot-reloads them when the backing file changes.
type RuleSet struct {
	mu       sync.RWMutex
	rules    []Rule
	path     string
	lastStat fileStat
	fallback float64 // score threshold used when rules list is empty (legacy mode)
}

// Load returns a RuleSet backed by path. If path is empty or the file does not
// exist, Evaluate uses fallbackThreshold for legacy score-based blocking.
func Load(path string, fallbackThreshold float64) *RuleSet {
	rs := &RuleSet{path: path, fallback: fallbackThreshold}
	rs.reload()
	return rs
}

// Evaluate returns the action for the given event + reputation state.
// It hot-reloads the rule file when mtime or size has changed since the last call.
func (rs *RuleSet) Evaluate(e proto.Event, rec store.ScoreRecord, b *BurstStore) Action {
	rs.maybeReload()

	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if len(rs.rules) == 0 {
		if rec.Score >= rs.fallback {
			return ActionBlock
		}
		return ActionNone
	}

	// burstCache memoises Count() calls for the same BurstWindow within one
	// Evaluate() invocation so we don't re-scan the slice per rule.
	type windowKey = time.Duration
	burstCache := make(map[windowKey]int)

	for _, r := range rs.rules {
		if r.Reason != "" && r.Reason != e.Reason {
			continue
		}
		if r.MinScore > 0 && rec.Score < r.MinScore {
			continue
		}
		if r.MinCorroboration > 0 && rec.Corroboration < r.MinCorroboration {
			continue
		}
		if r.AnchoredOnly && rec.StrangerSeen {
			continue
		}
		if r.MinBurst > 0 {
			w := r.BurstWindow.Duration
			cnt, ok := burstCache[w]
			if !ok {
				cnt = b.Count(e.IP, e.Reason, w)
				burstCache[w] = cnt
			}
			if cnt < r.MinBurst {
				continue
			}
		}
		return r.Action
	}
	return ActionNone
}

func (rs *RuleSet) maybeReload() {
	if rs.path == "" {
		return
	}
	info, err := os.Stat(rs.path)
	if err != nil {
		return
	}
	cur := fileStat{mtime: info.ModTime(), size: info.Size()}
	rs.mu.RLock()
	unchanged := cur == rs.lastStat
	rs.mu.RUnlock()
	if unchanged {
		return
	}
	rs.reload()
}

func (rs *RuleSet) reload() {
	if rs.path == "" {
		return
	}
	data, err := os.ReadFile(rs.path)
	if err != nil {
		return // file missing = legacy mode; suppress log spam on fresh installs
	}
	var loaded []Rule
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		log.Printf("rules: keeping last-good ruleset; parse error in %s: %v", rs.path, err)
		return
	}
	info, _ := os.Stat(rs.path)
	rs.mu.Lock()
	rs.rules = loaded
	if info != nil {
		rs.lastStat = fileStat{mtime: info.ModTime(), size: info.Size()}
	}
	rs.mu.Unlock()
}
```

- [ ] **Step 4: Run all rules tests**

```bash
go test ./internal/rules/... -v
```

Expected: all PASS. Example output:
```
--- PASS: TestBurstCount_Empty
--- PASS: TestBurstCount_WithinWindow
--- PASS: TestBurstCount_Eviction
--- PASS: TestBurstCount_DifferentReasonIsolated
--- PASS: TestEvaluate_LegacyFallback_Block
--- PASS: TestEvaluate_LegacyFallback_NoBlock
--- PASS: TestEvaluate_ReasonMatch
--- PASS: TestEvaluate_FirstMatchWins
--- PASS: TestEvaluate_MinCorroboration
--- PASS: TestEvaluate_AnchoredOnly
--- PASS: TestEvaluate_MinBurst
--- PASS: TestEvaluate_HotReload
--- PASS: TestEvaluate_CorruptFileKeepsLastGood
```

- [ ] **Step 5: Verify full suite still passes**

```bash
go test ./... 2>&1 | tail -20
```

Expected: all packages `ok`.

- [ ] **Step 6: Commit**

```bash
git add internal/rules/rule.go internal/rules/rule_test.go
git commit -m "feat(rules): add RuleSet — YAML rule loader with hot-reload and Evaluate()"
```

---

## Task 3: Config Changes

**Files:**
- Modify: `internal/config/config.go`

### Context

Add `RulesFile string` to `ReputationConfig` and a `RulesFilePath()` helper that resolves the path the same way as `TrustAnchorsFile()`. `Defaults()` leaves `RulesFile: ""` so existing deployments stay in legacy mode.

Current `ReputationConfig` (lines 44–49 of `internal/config/config.go`):
```go
type ReputationConfig struct {
    HalfLife         Duration `yaml:"half_life"`
    BlockThreshold   float64  `yaml:"block_threshold"`
    UnblockThreshold float64  `yaml:"unblock_threshold"`
    DecayInterval    Duration `yaml:"decay_interval"`
}
```

- [ ] **Step 1: Add `RulesFile` to `ReputationConfig`**

Edit `internal/config/config.go` — replace the `ReputationConfig` struct:

```go
// ReputationConfig tunes the scoring engine.
type ReputationConfig struct {
	HalfLife         Duration `yaml:"half_life"`
	BlockThreshold   float64  `yaml:"block_threshold"`
	UnblockThreshold float64  `yaml:"unblock_threshold"`
	DecayInterval    Duration `yaml:"decay_interval"`
	RulesFile        string   `yaml:"rules_file"` // empty = legacy threshold mode
}
```

- [ ] **Step 2: Add `RulesFilePath()` helper**

Append to `internal/config/config.go` after the `TrustCertsFile()` method:

```go
// RulesFilePath returns the path of the operator rule file. If rules_file is
// not set, it defaults to <store.dir>/rules.yaml (absent = legacy mode).
func (c *Config) RulesFilePath() string {
	if c.Reputation.RulesFile != "" {
		return c.Reputation.RulesFile
	}
	return filepath.Join(c.Store.Dir, "rules.yaml")
}
```

- [ ] **Step 3: Verify build**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add rules_file to ReputationConfig and RulesFilePath() helper"
```

---

## Task 4: Node Wiring

**Files:**
- Modify: `internal/node/node.go`

### Context

Two changes:

1. Add `rules *rules.RuleSet` and `burst *rules.BurstStore` fields to the `Node` struct and wire them in `New()`.
2. In `processLocal` and `ProcessRemote`, replace the `score >= n.cfg.Reputation.BlockThreshold` check with `n.rules.Evaluate(e, rec, n.burst)`. Because `rep.Record()` returns only `(float64, error)`, we call `n.rep.GetRecord(e.IP)` after recording to get the full `ScoreRecord` for `Evaluate()`.

**Current block-decision code in `processLocal` (lines 168–172):**
```go
if score >= n.cfg.Reputation.BlockThreshold {
    if err := n.sink.Block(e.IP); err != nil {
        log.Printf("node: block %s: %v", e.IP, err)
    }
}
```

**Current block-decision code in `ProcessRemote` (lines 217–221):**
```go
if score >= n.cfg.Reputation.BlockThreshold {
    if err := n.sink.Block(e.IP); err != nil {
        log.Printf("node: block %s: %v", e.IP, err)
    }
}
```

- [ ] **Step 1: Add fields to `Node` struct and wire in `New()`**

In `internal/node/node.go`:

Add import:
```go
"github.com/JoeRu/swarmguard/internal/rules"
```

Replace the `Node` struct definition:
```go
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
	trust      *trust.Store
	vouch      *proto.PeerCert // this node's own peer-cert, attached to published events
	rules      *rules.RuleSet
	burst      *rules.BurstStore
}
```

Replace the `return &Node{...}` statement at the end of `New()`:
```go
	return &Node{
		cfg:        cfg,
		transport:  t,
		store:      s,
		rep:        eng,
		sources:    sources,
		sink:       sink,
		neverblock: nbl,
		selfID:     selfID,
		trust:      ts,
		vouch:      vouch,
		rules:      rules.Load(cfg.RulesFilePath(), cfg.Reputation.BlockThreshold),
		burst:      rules.NewBurstStore(),
	}, nil
```

- [ ] **Step 2: Replace block decision in `processLocal`**

Replace the existing `processLocal` function body with:

```go
func (n *Node) processLocal(ctx context.Context, e proto.Event) {
	if n.neverblock.Contains(e.IP) {
		return
	}
	e.ReporterID = n.selfID
	e.Vouch = n.vouch
	if _, err := n.rep.Record(e.IP, e.Reason, n.selfID, 1.0, n.selfID, true); err != nil {
		log.Printf("node: record local %s: %v", e.IP, err)
		return
	}
	n.burst.Record(e.IP, e.Reason, time.Now())
	rec, _ := n.rep.GetRecord(e.IP)
	switch n.rules.Evaluate(e, rec, n.burst) {
	case rules.ActionBlock:
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		}
	case rules.ActionWatch:
		log.Printf("node: watch %s reason=%s score=%.1f", e.IP, e.Reason, rec.Score)
	}
	if n.transport != nil {
		if err := n.transport.Publish(ctx, e); err != nil {
			log.Printf("node: publish %s: %v", e.IP, err)
		}
	}
}
```

- [ ] **Step 3: Replace block decision in `ProcessRemote`**

Inside `ProcessRemote`, replace the final block:
```go
	weight, group, anchored := n.trust.Resolve(e.ReporterID)
	score, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, weight, group, anchored)
	if err != nil {
		log.Printf("node: record remote %s: %v", e.IP, err)
		return
	}
	if score >= n.cfg.Reputation.BlockThreshold {
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		}
	}
```

with:
```go
	weight, group, anchored := n.trust.Resolve(e.ReporterID)
	if _, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, weight, group, anchored); err != nil {
		log.Printf("node: record remote %s: %v", e.IP, err)
		return
	}
	n.burst.Record(e.IP, e.Reason, time.Now())
	rec, _ := n.rep.GetRecord(e.IP)
	switch n.rules.Evaluate(e, rec, n.burst) {
	case rules.ActionBlock:
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		}
	case rules.ActionWatch:
		log.Printf("node: watch %s reason=%s score=%.1f", e.IP, e.Reason, rec.Score)
	}
```

- [ ] **Step 4: Build**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 5: Run all tests**

```bash
go test ./...
```

Expected: all packages `ok`. The existing adversarial and integration tests still pass because they use `BlockThreshold: 1_000_000` / `1000` — with no rules.yaml at the temp dir, `RuleSet.Evaluate()` falls back to the legacy threshold, which is never reached.

- [ ] **Step 6: Commit**

```bash
git add internal/node/node.go
git commit -m "feat(node): wire rules engine — replace score-threshold block with RuleSet.Evaluate()"
```

---

## Task 5: Example Rules File and CHANGELOG

**Files:**
- Create: `deploy/examples/rules.yaml`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Create example rules file**

Create `deploy/examples/rules.yaml`:

```yaml
# SwarmGuard — example block rules
#
# Copy this file to your store directory (e.g. data/reputation/rules.yaml)
# and set `reputation.rules_file` in config.yaml, or rely on the default
# auto-discovery at <store.dir>/rules.yaml.
#
# Rules are evaluated top-to-bottom; the first matching rule wins.
# All conditions in a rule are ANDed — omit a field to skip that check.
#
# Actions: block | watch | ignore

# Honeypot command execution — high-confidence; block on single corroborator.
- name: honeypot-shell-exec
  reason: ssh-post-auth-command
  min_corroboration: 1
  action: block

# SSH auth success on honeypot — attacker authenticated; block immediately.
- name: honeypot-auth-success
  reason: ssh-auth-success
  min_corroboration: 1
  action: block

# SMTP auth bruteforce confirmed by 2+ reporters.
- name: smtp-brute-consensus
  reason: smtp-auth-bruteforce
  min_corroboration: 2
  action: block

# IMAP auth bruteforce confirmed by 2+ reporters.
- name: imap-brute-consensus
  reason: imap-auth-bruteforce
  min_corroboration: 2
  action: block

# SSH auth bruteforce burst — 15 events in 10 minutes triggers block.
- name: ssh-brute-burst
  reason: ssh-auth-bruteforce
  min_burst: 15
  burst_window: 10m
  action: block

# SSH probe seen by 3+ distinct reporters — coordinated scan.
- name: ssh-probe-consensus
  reason: ssh-probe
  min_corroboration: 3
  action: block

# Score-based fallback — catches everything that didn't match a specific rule.
- name: score-fallback
  min_score: 75
  action: block
```

- [ ] **Step 2: Add CHANGELOG entry**

Prepend inside the `## [Unreleased]` section of `CHANGELOG.md` (add before the existing `### Added` block):

```markdown
### Added (rules engine)
- **Pure YAML rules engine** — `internal/rules` package replaces the single
  `block_threshold` scalar with a hot-reloadable `rules.yaml` file.
  - `RuleSet.Evaluate(event, scoreRecord, burstStore)` — first-match rule
    evaluation with AND conditions: `reason`, `min_score`, `min_corroboration`,
    `anchored_only`, `min_burst`+`burst_window`.
  - `BurstStore` — in-memory sliding-window counter per (ip, reason); resets on
    restart (burst = happening now).
  - Hot-reload: file re-read on mtime+size change; corrupt file keeps last-good.
  - Actions: `block`, `watch` (log only), `ignore`.
  - Legacy fallback: if `rules.yaml` is absent, falls back to
    `score >= block_threshold` — zero config change for existing deployments.
  - `deploy/examples/rules.yaml` — default rules covering SSH/SMTP/IMAP honeypot
    events, burst detection, and a score-based fallback.
- `internal/config` — `ReputationConfig.RulesFile string` (`yaml:"rules_file"`)
  and `Config.RulesFilePath()` helper.
```

- [ ] **Step 3: Run full suite + adversarial**

```bash
go test ./...
make adversarial
make build
```

Expected: all pass, binaries built cleanly.

- [ ] **Step 4: Commit**

```bash
git add deploy/examples/rules.yaml CHANGELOG.md
git commit -m "feat(rules): add example rules.yaml and document rules engine in CHANGELOG"
```

---

## Self-Review Checklist

**Spec coverage:**
- ✅ Hot-reload (fileStat mtime+size) — Task 2, `maybeReload()`
- ✅ First-match-wins — Task 2, `Evaluate()` loop
- ✅ All conditions: reason, min_score, min_corroboration, anchored_only, min_burst+burst_window — Task 2
- ✅ Actions: block, watch, ignore — Task 2 + Task 4
- ✅ BurstStore in-memory sliding window — Task 1
- ✅ Legacy fallback when no rules file — Task 2 `Evaluate()` + Task 3 `RulesFilePath()`
- ✅ Config: `RulesFile` + `RulesFilePath()` — Task 3
- ✅ Node wiring: processLocal + ProcessRemote — Task 4
- ✅ Example rules.yaml — Task 5
- ✅ CHANGELOG — Task 5

**Type consistency across tasks:**
- `BurstStore.Record(ip, reason string, now time.Time)` — defined Task 1, used Task 4 ✅
- `BurstStore.Count(ip, reason string, window time.Duration) int` — defined Task 1, called in Task 2 `Evaluate()` ✅
- `RuleSet.Evaluate(e proto.Event, rec store.ScoreRecord, b *BurstStore) Action` — defined Task 2, called Task 4 ✅
- `rules.Load(path string, fallbackThreshold float64) *RuleSet` — defined Task 2, called Task 4 ✅
- `cfg.RulesFilePath() string` — defined Task 3, called Task 4 ✅
- `rules.ActionBlock`, `rules.ActionWatch`, `rules.ActionIgnore`, `rules.ActionNone` — defined Task 2, used Task 4 ✅
