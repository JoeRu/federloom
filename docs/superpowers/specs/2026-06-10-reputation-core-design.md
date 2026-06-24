# Reputation Core + Cowrie Ingest + ipset Enforcement — Design Spec

**Date:** 2026-06-10
**Status:** Approved

## 1. Architecture Overview

Pipeline:

```
cowrie.json (JSONL)
    │
    ▼
internal/ingest/honeypot.go   (trust=1.0, local anchor)
    │
    ▼  chan proto.Event
internal/node/node.go          (composition root)
    │                 ▲
    │                 │ remote events (trust=0.3)
    ▼                 │
internal/reputation/           (decay + corroboration + BadgerDB)
    │
    ▼
internal/enforce/ipset.go      (or nftables.go — swappable via config)
```

Transport (gossipsub) feeds remote events into the same reputation pipeline via `processRemote()`. The node layer is the only place that knows about all three planes.

## 2. Data Store

**Package:** `internal/store`

BadgerDB wrapper exposing:

```go
type BadgerStore struct { ... }
func (s *BadgerStore) GetScore(ip string) (proto.ScoreEntry, error)
func (s *BadgerStore) PutScore(ip string, e proto.ScoreEntry) error
func (s *BadgerStore) DeleteScore(ip string) error
func (s *BadgerStore) ScanScores(fn func(ip string, e proto.ScoreEntry) error) error
```

- Keys: raw IP strings (UTF-8)
- Values: JSON-serialised `proto.ScoreEntry`
- BadgerDB TTL = 3 × half-life (default 21 days) — serves as GDPR deletion mechanism (spec §9)
- `proto.ScoreEntry` gains two new fields: `Score float64` and `Corroboration int`

## 3. Reputation Engine

**Package:** `internal/reputation`

**Decay** (lazy, applied at read time):

```
score(t) = score₀ × exp(−ln2 × Δt / halfLife)
```

Default half-life: 7 days. `LastSeen` timestamp stored in `ScoreEntry`.

**Accumulation** (logistic, caps at 100):

```
score += trust × reportWeight × (1 − score/100)
```

Report weights by reason:

| Reason | Weight |
|---|---|
| `ssh-auth-success` | 40 |
| `ssh-auth-bruteforce` | 10 |
| `ssh-post-auth-command` | 10 |
| `ssh-probe` | 2 |
| `ssh-unknown` | 2 |

Trust values:
- Local Cowrie: `1.0`
- Remote peer: `0.3`

**Corroboration:** `Corroboration` = count of distinct `ReporterID`s seen for this IP. Same reporter reporting twice does not increment. Stored in `ScoreEntry`.

Block threshold: 75. Unblock threshold: 60 (hysteresis prevents flapping).

## 4. Cowrie Ingest Plugin

**File:** `internal/ingest/honeypot.go`

Implements `ingest.Source`. Tails Cowrie's JSONL log file by polling (default 1s interval). Seeks to end of file on startup; reopens on shrink detection (log rotation).

**Event mapping:**

| Cowrie `eventid` | `proto.Event.Reason` | Weight |
|---|---|---|
| `cowrie.login.success` | `ssh-auth-success` | 40 |
| `cowrie.login.failed` | `ssh-auth-bruteforce` | 10 |
| `cowrie.command.input` | `ssh-post-auth-command` | 10 |
| `cowrie.session.connect` | `ssh-probe` | 2 |
| (any other) | `ssh-unknown` | 2 |

Lines with empty `src_ip` are skipped. Unknown `eventid` values are emitted with `ssh-unknown` reason (safe floor, does not inflate scores).

All Cowrie events get `Trust: 1.0` and `ReporterID` = local node's peer ID (ground-truth anchor, spec §4.1).

Backpressure: if the output channel is full, drop the event (high-volume honeypot noise; blocking is worse than loss).

**Config:**
```yaml
ingest:
  honeypot:
    enabled: true
    log_file: /opt/cowrie/var/log/cowrie/cowrie.json
    poll_interval: 1s
```

## 5. Enforcement Backends

Both `internal/enforce/ipset.go` and `internal/enforce/nftables.go` implement `enforce.Sink`. Backend selected by config — no code changes needed to switch.

**Interface:**
```go
Block(ip string) error
Unblock(ip string) error
```

**Config:**
```yaml
enforce:
  backend: ipset          # ipset | nftables
  set_name: federloom
  block_threshold: 75
  unblock_threshold: 60
  chain: DOCKER-USER      # ipset backend: INPUT | DOCKER-USER | FORWARD
  nft_hook: input         # nftables backend: input | forward
```

**ipset backend:**
- Creates `hash:ip` set (idempotent `-exist`)
- Default chain: `DOCKER-USER` — Docker preserves this chain across `docker network` changes; `INPUT`-only rules silently miss traffic to exposed containers
- Startup warning logged if `chain=INPUT` and Docker is detected

**nftables backend:**
- Creates named set in `inet filter` table
- `input` hook: host traffic only; `forward` hook: covers Docker-forwarded traffic
- Same Docker caveat as ipset — use `forward` hook in Docker environments

**Docker caveat (startup log):**
```
WARN enforce: chain=INPUT will not block traffic to Docker containers;
     set chain=DOCKER-USER or nft_hook=forward for Docker environments
```

**Neverblock:** checked in the node layer before dispatch to any backend. IPs in the local-only whitelist are never passed to `Block()` (spec §6.2 / invariant 3).

## 6. Node Wiring

**File:** `internal/node/node.go`

Composition root connecting all three planes.

```go
type Node struct {
    cfg       *config.Config
    transport *transport.Node
    store     *store.BadgerStore
    rep       *reputation.Engine
    ingest    []ingest.Source
    enforce   enforce.Sink
}
```

`Run(ctx)` starts components in order: store → enforce → transport → ingest. Shutdown reverses the order on context cancellation.

**Local event path** (`processLocal`):
1. Neverblock check — skip if whitelisted
2. `rep.Record(ip, trust=1.0, reason, reporterID=self.PeerID)`
3. If score ≥ block_threshold → `enforce.Block(ip)`
4. Gossip event to peers via transport

**Remote event path** (`processRemote`):
1. Neverblock check
2. `rep.Record(ip, trust=0.3, reason, reporterID=event.ReporterID)`
3. If score ≥ block_threshold → `enforce.Block(ip)`
4. Do not re-gossip (gossipsub deduplicates via message IDs)

**Decay unblock ticker** (default 1h): scan all scores, apply decay, call `enforce.Unblock(ip)` for any IP that drops below `unblock_threshold`.

**`cmd/federloomd/main.go`:** replace synthetic event loop with `node.New(cfg).Run(ctx)`. `--config` flag selects YAML config file (default `config.yaml`).

## 7. Testing Strategy

### Unit tests (no I/O)

- `internal/reputation/decay_test.go` — half-life math at t=0, t=halfLife, t=2×halfLife; logistic cap at 100
- `internal/reputation/corroboration_test.go` — same reporter twice does not increment corroboration; two distinct reporters do
- `internal/ingest/honeypot_test.go` — temp JSONL file, append lines, assert correct `proto.Event` fields; unknown eventid → `ssh-unknown`; empty `src_ip` skipped

### Integration tests (real BadgerDB, no network)

- `test/integration/reputation_store_test.go` — `Record()` / `GetScore()` round-trip; decay across a persisted score; TTL expiry (100ms half-life for speed)
- `test/integration/pipeline_test.go` — ingest → reputation → mock enforce.Sink; assert `Block()` called after threshold; assert neverblock IP never reaches `Block()`

### Adversarial tests (extend `test/adversarial/`)

- `sybil_ingest_test.go` — 50 remote peers report same IP; corroboration count caps; score does not exceed logistic ceiling
- `poisoning_test.go` — remote peer reports a neverblock IP; `Block()` never called

### Smoke test extension

Extend `scripts/dev/smoke-test.sh`: mount synthetic `cowrie.json` into leaf1; assert leaf2/leaf3 both block `198.51.100.1` via `ipset list federloom` inside the container.

### Phase 2: Real-life validation

Operator-provided remote machine running a real Cowrie honeypot. Validate that:
- `cowrie.json` is written in the expected JSONL format
- FederLoom ingest plugin tails and parses it correctly under live traffic
- Scores accumulate and IPs are blocked as expected

Setup instructions and remote machine provisioning to be covered when the machine is available.
