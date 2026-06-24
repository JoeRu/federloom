# Rules Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the single `block_threshold` scalar with a hot-reloadable YAML rule file that drives all block decisions via named, composable rules evaluated against event properties, reputation score, corroboration, and burst counters.

**Architecture:** A new `internal/rules` package owns rule loading, evaluation, and burst tracking. The reputation engine continues to accumulate scores and maintain audit state; blocking is now decided by `RuleSet.Evaluate()` rather than `score >= threshold`. First matching rule wins; unblock remains score/decay driven and is unchanged.

**Tech Stack:** Go 1.22, `gopkg.in/yaml.v3` (already used in config), `sync.RWMutex` for burst store, fileStat hot-reload pattern (same as `internal/trust`).

---

## Context: What already exists

- `internal/reputation/engine.go` — `Record()` accumulates logistic score, stranger cap, corroboration groups; `Decay()` applies exponential half-life. Score is available as `ScoreRecord.Score`.
- `internal/store/store.go` — `ScoreRecord` has `Score`, `Corroboration`, `Groups`, `StrangerSeen`, `StrangerContrib`, `Reasons`, `ReporterIDs`.
- `internal/enforce/` — `Sink` interface with `Block(ip)`/`Unblock(ip)`; ipset and nftables backends.
- `internal/node/node.go` — `processLocal` and `ProcessRemote` call `n.sink.Block(ip)` when `score >= cfg.Reputation.BlockThreshold`. This is the integration point.
- `internal/trust/store.go` — fileStat hot-reload pattern (mtime+size) to copy for rules hot-reload.
- `internal/config/config.go` — `ReputationConfig` with `BlockThreshold float64`; add `RulesFile string` here.

---

## Architecture

```
ingest event
     │
     ▼
reputation.Record()     ← unchanged; score + corroboration updated in BadgerDB
     │
     ▼
burst.Record(ip, reason, now)   ← in-memory sliding window updated
     │
     ▼
rules.Evaluate(event, scoreRecord, burstStore)
     │
     ├── first matching rule → action: block  → sink.Block(ip)
     ├── first matching rule → action: watch  → log only
     ├── first matching rule → action: ignore → no-op
     └── no match            → legacy fallback: score >= block_threshold
```

Unblock path is unchanged: periodic decay below `unblock_threshold` triggers `sink.Unblock(ip)`.

---

## Rule File Format

Path: configurable via `reputation.rules_file` in `config.yaml`. Default: `<store.dir>/rules.yaml`. Empty string = legacy mode (no rules file; score threshold governs).

Rules are a YAML list evaluated top-to-bottom; **first matching rule wins**. All conditions present in a rule must match (AND). Missing conditions are not checked.

```yaml
# deploy/examples/rules.yaml

- name: honeypot-shell-exec
  reason: ssh-post-auth-command
  min_corroboration: 1
  action: block

- name: smtp-brute-consensus
  reason: smtp-auth-bruteforce
  min_corroboration: 2
  action: block

- name: ssh-brute-burst
  reason: ssh-auth-bruteforce
  min_burst: 15
  burst_window: 10m
  action: block

- name: ssh-probe-consensus
  reason: ssh-probe
  min_corroboration: 3
  action: block

- name: score-fallback
  min_score: 75
  action: block
```

### Conditions (all optional; omit = condition not checked)

| Field | Type | Meaning |
|---|---|---|
| `reason` | string | Event.Reason exact match |
| `min_score` | float64 | ScoreRecord.Score ≥ value |
| `min_corroboration` | int | ScoreRecord.Corroboration ≥ value |
| `anchored_only` | bool | StrangerSeen must be false (all reporters anchored) |
| `min_burst` | int | Events for (ip, reason) within `burst_window` ≥ value |
| `burst_window` | duration | Sliding window for burst count (e.g. `5m`, `1h`) |

### Actions

| Value | Effect |
|---|---|
| `block` | Call `sink.Block(ip)` |
| `watch` | Log event; no blocking |
| `ignore` | Suppress; no log, no block |

---

## New Package: `internal/rules`

### `internal/rules/rule.go`

```go
package rules

import (
    "os"
    "sync"
    "time"

    "gopkg.in/yaml.v3"
    "github.com/JoeRu/federloom/internal/store"
    "github.com/JoeRu/federloom/pkg/proto"
)

type Action string

const (
    ActionBlock  Action = "block"
    ActionWatch  Action = "watch"
    ActionIgnore Action = "ignore"
    ActionNone   Action = ""   // no rule matched
)

type Rule struct {
    Name             string        `yaml:"name"`
    Reason           string        `yaml:"reason"`
    MinScore         float64       `yaml:"min_score"`
    MinCorroboration int           `yaml:"min_corroboration"`
    AnchoredOnly     bool          `yaml:"anchored_only"`
    MinBurst         int           `yaml:"min_burst"`
    BurstWindow      time.Duration `yaml:"burst_window"`
    Action           Action        `yaml:"action"`
}

type RuleSet struct {
    mu       sync.RWMutex
    rules    []Rule
    path     string
    lastStat fileStat
    fallback float64  // block_threshold used when no rules file
}

type fileStat struct {
    mtime time.Time
    size  int64
}

// Load returns a RuleSet backed by path. If path is empty or missing the
// RuleSet uses fallbackThreshold for legacy score-based blocking.
func Load(path string, fallbackThreshold float64) *RuleSet {
    rs := &RuleSet{path: path, fallback: fallbackThreshold}
    rs.reload() // best-effort; missing file is not an error
    return rs
}

// Evaluate returns the action for the given event + reputation state.
// It hot-reloads the rule file when the file has changed since last check.
func (rs *RuleSet) Evaluate(e proto.Event, rec store.ScoreRecord, b *BurstStore) Action {
    rs.maybeReload()
    rs.mu.RLock()
    defer rs.mu.RUnlock()

    if len(rs.rules) == 0 {
        // Legacy fallback
        if rec.Score >= rs.fallback {
            return ActionBlock
        }
        return ActionNone
    }

    burstCache := make(map[time.Duration]int) // memoise burst counts per window

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
            cnt, ok := burstCache[r.BurstWindow]
            if !ok {
                cnt = b.Count(e.IP, e.Reason, r.BurstWindow)
                burstCache[r.BurstWindow] = cnt
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
        return // missing file = legacy mode; no log spam
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

### `internal/rules/burst.go`

```go
package rules

import (
    "sync"
    "time"
)

// BurstStore tracks per-(ip,reason) event timestamps for sliding-window burst detection.
// State is in-memory only; resets on daemon restart (burst = happening right now).
type BurstStore struct {
    mu      sync.Mutex
    entries map[burstKey][]time.Time
}

type burstKey struct{ ip, reason string }

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
// Evicts stale entries as a side effect.
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

---

## Config Changes

`internal/config/config.go` — add `RulesFile` to `ReputationConfig`:

```go
type ReputationConfig struct {
    HalfLife         Duration `yaml:"half_life"`
    BlockThreshold   float64  `yaml:"block_threshold"`   // legacy fallback
    UnblockThreshold float64  `yaml:"unblock_threshold"`
    DecayInterval    Duration `yaml:"decay_interval"`
    RulesFile        string   `yaml:"rules_file"`         // NEW
}
```

`Defaults()` sets `RulesFile: ""` (legacy mode until operator opts in).

Add helper to `Config`:

```go
func (c *Config) RulesFilePath() string {
    if c.Reputation.RulesFile != "" {
        return c.Reputation.RulesFile
    }
    return filepath.Join(c.Store.Dir, "rules.yaml")
}
```

---

## Node Integration

`internal/node/node.go`:

```go
// New() — add fields and construction
n.rules = rules.Load(cfg.RulesFilePath(), cfg.Reputation.BlockThreshold)
n.burst = rules.NewBurstStore()

// processLocal — replace score >= threshold block:
rec, _ := n.rep.GetRecord(e.IP)
n.burst.Record(e.IP, e.Reason, time.Now())
action := n.rules.Evaluate(e, rec, n.burst)
if action == rules.ActionBlock {
    if err := n.sink.Block(e.IP); err != nil {
        log.Printf("node: block %s: %v", e.IP, err)
    }
}

// ProcessRemote — same replacement
```

`watch` action: `log.Printf("node: watch %s reason=%s score=%.1f", e.IP, e.Reason, rec.Score)`

---

## Backwards Compatibility

- `rules_file` defaults to `""` in `Defaults()`.
- When `RulesFilePath()` resolves to a path that does not exist, `RuleSet.Evaluate()` falls back to `score >= block_threshold`.
- Existing deployments with no `rules.yaml` behave identically to today.
- Operators opt in by copying `deploy/examples/rules.yaml` to their data directory.

---

## Tests

### `internal/rules/rule_test.go`
- `TestEvaluate_ReasonMatch` — rule with `reason` fires only on matching reason
- `TestEvaluate_FirstMatchWins` — two matching rules; first action returned
- `TestEvaluate_NoMatch_LegacyFallback` — empty ruleset + score=80 + fallback=75 → block
- `TestEvaluate_NoMatch_LegacyNoBlock` — empty ruleset + score=50 + fallback=75 → none
- `TestEvaluate_MinCorroboration` — fires only when corroboration ≥ N
- `TestEvaluate_AnchoredOnly` — fires only when StrangerSeen=false
- `TestEvaluate_MinBurst` — fires only when burst count ≥ N within window
- `TestEvaluate_HotReload` — write rules.yaml, evaluate, rewrite, evaluate again; second call uses new rule

### `internal/rules/burst_test.go`
- `TestBurstCount_Empty` — zero count on empty store
- `TestBurstCount_WithinWindow` — events within window counted
- `TestBurstCount_Eviction` — old events outside window excluded

---

## Files Created / Modified

| Action | Path |
|---|---|
| Create | `internal/rules/rule.go` |
| Create | `internal/rules/burst.go` |
| Create | `internal/rules/rule_test.go` |
| Create | `internal/rules/burst_test.go` |
| Create | `deploy/examples/rules.yaml` |
| Modify | `internal/config/config.go` — add `RulesFile`, `RulesFilePath()` |
| Modify | `internal/node/node.go` — add `rules`+`burst` fields, replace block decision |
| Modify | `CHANGELOG.md` |
