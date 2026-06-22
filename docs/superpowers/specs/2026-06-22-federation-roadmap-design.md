# Federation Roadmap Design

**Date:** 2026-06-22
**Status:** Approved — ready for implementation planning
**Scope:** Five sequential implementation phases that complete SwarmGuard's federation
layer and bring remaining spec gaps to production quality.

---

## Context

The audit of 2026-06-22 identified the following spec gaps ranked by impact:

| Gap | Spec ref | Phase |
|-----|----------|-------|
| OriginTrace phantom (federation feedback loop unmitigated) | §5.2 / Problem K | 1 |
| Federation discount function missing | §5.2 | 1 |
| Federation discovery (new §14) | §14 | 1 |
| Event signing dead field | §7.1 | 1 |
| Defederation not implemented | §5.2 / Problem L | 1 |
| Whitelist store missing | §6.2 / §7.4 | 2 |
| `swarmctl whitelist` subcommand missing | §6.2 | 2 |
| `install.sh` TODO unresolved | §6.2 | 2 |
| Bloom filter not implemented | §11.3 | 3 |
| Pull-on-demand (DNSBL model) not wired | §11.4 | 3 |
| Graceful degradation / load shedding | §11.5 | 4 |
| Resource budget (CPU/bandwidth cap) | §11.5 | 4 |
| Reporter privacy (OriginTrace anonymisation option) | §12 Problem E | 5 |

---

## Phase 1 — Federation Semantics + Discovery

**Goal:** Make federation correct and discoverable.

### 1a. OriginTrace wiring

`proto.Event.OriginTrace` is defined but never set or validated.
Without it, two mutually federated nodes (A↔B) count every report twice (Problem K).

**Design:**
- `processLocal`: set `e.OriginTrace = []string{n.selfID}` before publishing
- `ProcessRemote`: reject events that already contain `n.selfID` in `OriginTrace`
  (feedback loop guard); append `n.selfID` before re-publishing downstream
- Cap trace length at 8 hops to prevent unbounded growth; drop events exceeding cap

### 1b. Federation trust discount

Imported events from non-anchored federations should carry a hop-based discount so
that information dilutes as it travels further from its source.

**Design:**
- New config: `trust.federation_discount` (float64, default 0.5)
- In `ProcessRemote`: `effectiveWeight = weight * pow(federation_discount, len(OriginTrace))`
- Anchored reporters (weight from `trust.Store.Resolve`) are exempt from discount
- This addresses spec §5.2's "trust discount over federation hops"

### 1c. Federation discovery (spec §14)

New subsystem: `internal/discovery`.

**Components:**
- `discovery.Manager` — owns both advertisement and peer-finding goroutines
- DHT rendezvous via `go-libp2p/p2p/discovery/routing.NewRoutingDiscovery` wrapping
  the existing `*dht.IpfsDHT`; rendezvous point `/swarmguard/v1/peers`
- Relay list: `internal/discovery/relaylist.go` — loads `relay-list.json` (bundled
  at `internal/resources/relay-list.json`; overridable via config `discovery.relay_list_path`)
- `relay-list.json` schema: `[{"peer_id": "12D3...", "addrs": ["/ip4/..."], "label": "..."}]`
  (no signature in Phase 1; signature verification is Phase 5 hardening)
- Config additions in `internal/config`: `discovery.advertise` (bool, default true),
  `discovery.discover` (bool, default true), `discovery.relay_list_path` (string)
- `Node.New()` in `internal/node/node.go` starts `discovery.Manager` when transport ≠ nil

**Peer connection flow:**
1. On start: load relay list → connect to relay peers → bootstrap DHT
2. If `discover: true`: start `routing.Advertise` goroutine + `routing.FindPeers` loop
   (30s interval, connect to found peers not already connected)
3. Newly connected peers are strangers; `trust.Store.Resolve` returns `stranger_weight`

### 1d. Event signing

`proto.Event.Signature` is never set or verified. Without it, report authenticity
relies entirely on gossipsub transport signing (which only authenticates the last hop,
not the origin across federation hops).

**Design:**
- `processLocal`: sign `sha256(ip ‖ reason ‖ ts.RFC3339Nano ‖ reporterID)` with
  the node's Ed25519 identity key; set `e.Signature`
- `ProcessRemote`: verify signature against `e.ReporterID` (the libp2p peer ID
  embeds the public key); drop events with invalid signatures
- For events received from non-direct-federation hops (OriginTrace len > 1),
  signature still verifies the original reporter — not the relaying node

### 1e. Defederation

A compromised or malicious subnet must be removable without restarting the daemon.

**Design:**
- New config list: `trust.blocked_peers []string` (peer IDs)
- `ProcessRemote`: early-return if `re.From` is in `blocked_peers`
- `swarmctl trust block PEER_ID` / `swarmctl trust unblock PEER_ID` — edit
  `blocked-peers.json` (same hot-reload pattern as `anchors.json`)
- `trust.Store` gains `IsBlocked(peerID string) bool` method

---

## Phase 2 — Install Script + Local Whitelist

**Goal:** Fulfill spec §6.2. The install script currently has a dead TODO.

### 2a. Whitelist store

New file: `internal/store/whitelist.go`
- `WhitelistStore` backed by BadgerDB (or a separate JSON file — JSON preferred
  for human-readability and auditability; whitelist changes should be diff-able)
- Key: `ip_or_range`, Value: `proto.WhitelistEntry{Scope, Source}`
- `Contains(ip string) bool` — checks local-only entries first (fast path)
- `Add(entry proto.WhitelistEntry) error`
- `Remove(ipOrRange string) error`
- `List() ([]proto.WhitelistEntry, error)`

### 2b. Wire whitelist into enforce path

`internal/node/node.go`: after `neverblock.Contains` check, also check
`whitelistStore.Contains` for `scope: local-only` entries. These suppress local
blocks but are never published (spec §6.2 invariant: local-only is never federated).

### 2c. `swarmctl whitelist` subcommand

New file: `cmd/swarmctl/whitelist.go`
```
swarmctl whitelist add --scope local-only CIDR_OR_IP
swarmctl whitelist add --scope shared-vote CIDR_OR_IP
swarmctl whitelist remove CIDR_OR_IP
swarmctl whitelist list
```

### 2d. Complete install.sh

Replace the TODO line with an actual call to `swarmctl whitelist add --scope local-only`
for each confirmed entry. The script already detects entries; it just needs to persist them.

---

## Phase 3 — Sync Model: Bloom + Pull-on-demand

**Goal:** Implement the three-tier architecture from spec §11.2/§11.3/§11.4.

### 3a. Bloom filter pre-filter

New file: `internal/store/bloom.go`
- Wrap `github.com/bits-and-blooms/bloom/v3` (already available or add dep)
- `BloomFilter` loaded/rebuilt from BadgerDB on startup; updated on every `PutScore`
- `MightContain(ip string) bool` — returns false → skip BadgerDB lookup entirely
- `BadgerStore` gains `Bloom() *BloomFilter` accessor
- Node's enforcement hot path (`processLocal`, `ProcessRemote`) checks bloom before
  `store.GetScore`; false → skip score lookup (IP definitely not in reputation store)

### 3b. Pull-on-demand via DHT

New file: `internal/transport/dht_query.go`
- `Node.QueryScore(ctx, ip string) (*proto.ScoreEntry, error)` — DHT `GetValue` on
  key `/swarmguard/score/v1/<ip>`; returns nil if not found (locally or remotely)
- Nodes with a score above `block_threshold` publish their score to DHT
  (`PutValue`) after every `Record` call; TTL matches score's BadgerDB TTL
- Consuming nodes (those that don't yet have an entry for an IP) call `QueryScore`
  on first contact with an IP not in local store — this is the "pull-on-demand" path
- Local TTL cache: if a DHT query returned a score, cache it for `dht_cache_ttl`
  (config, default 15m) to avoid repeat DHT lookups

### 3c. Config additions

```yaml
sync:
  mode: hybrid          # push | pull | hybrid (default: hybrid)
  dht_cache_ttl: 15m
  bloom_fpr: 0.01       # bloom false-positive rate
```

---

## Phase 4 — Resource Budget + Load Shedding

**Goal:** Spec §11.5 "the protection mechanism must never itself be the performance problem."

### 4a. CPU/bandwidth budget

- New config section: `resources.max_gossip_bandwidth_kbps` (default: 512)
  and `resources.max_cpu_percent` (default: 10)
- Gossip publisher: rate-limit `transport.Publish` calls using a token bucket
  (`golang.org/x/time/rate`)
- DHT queries: separate token bucket for outbound DHT traffic

### 4b. Graceful degradation

- New state in `Node`: `underAttack bool` (set when local `ingestChans` backpressure
  exceeds a threshold — channel buffer > 80% full for > 10s)
- When `underAttack`:
  - Suspend outbound gossip publishing (protect local first)
  - Suspend DHT pull queries
  - Continue local scoring and enforcement
  - Log "node: under attack, suspending federation — local-only mode"
  - Auto-recover when buffer drops below 20% for > 30s
- Config: `resources.attack_buffer_threshold` (default: 0.8)

### 4c. `nice`/cgroup hints

- `swarmd` calls `syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)` on startup
  (configurable: `resources.nice_level`, default 10)
- Document cgroup setup in `docs/onboarding/`

---

## Phase 5 — Reporter Privacy Decision

**Goal:** Resolve spec §12 Problem E: "anonymity vs. accountability" for the OriginTrace.

**The tension:**
- Full OriginTrace (current design) reveals which nodes relayed a report — leaks network topology
- No OriginTrace breaks the anti-feedback-loop guard (Problem K)
- Tor-style onion routing adds complexity and latency

**Design decision (to be confirmed during plan writing):**
- Keep OriginTrace for the anti-loop guard (its primary purpose)
- Add config `privacy.strip_origin_trace_on_relay` (default: false)
  - When true: relay nodes replace `OriginTrace` with a single opaque HMAC of the
    original trace (keyed with a local secret); preserves loop detection for events
    this node has seen before without leaking the full hop list
  - When false: full trace (current behaviour, better auditability)
- Prominently document the trade-off in `docs/onboarding/02-whitelist.md`

---

## Implementation Sequence

Each phase produces a separate implementation plan:

1. `2026-06-22-phase1-federation-semantics.md` — OriginTrace, discount, discovery, signing, defederation
2. `2026-06-22-phase2-whitelist.md` — whitelist store, swarmctl whitelist, install.sh completion
3. `2026-06-22-phase3-sync-model.md` — bloom filter, DHT pull-on-demand, sync config
4. `2026-06-22-phase4-resource-budget.md` — token bucket, graceful degradation, nice level
5. `2026-06-22-phase5-reporter-privacy.md` — OriginTrace HMAC option, docs

Phases are sequential: each plan's tests must pass before starting the next.
