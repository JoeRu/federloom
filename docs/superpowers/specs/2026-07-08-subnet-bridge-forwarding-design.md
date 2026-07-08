# Subnet-Bridge Forwarding + Functional Origin-Tracing (Sub-project E1)

**Status:** Design approved 2026-07-08
**Source:** Remediation roadmap sub-project E, first piece (E1). Critique P1-5
(origin-tracing / hop-discount inert at runtime); spec §5.2 (federation import,
hop-discount, origin tracking / Problem K), §11.4 (relay hierarchy).
**Prerequisite:** batches A+B, stranger-block guarantee, IPv6 normalization —
all merged to `main`.

---

## 1. Problem & framing

`internal/node/node.go` carries a per-hop `FederationDiscount` and an A→B→A
feedback-loop guard keyed on `OriginTrace`, but both are **inert at runtime**.
The code comment states why: gossipsub floods the originator's signed bytes
unchanged, no node re-publishes, so `OriginTrace` never grows past the
originator (`len == 1`), and `e.SubnetID` is in fact **never set anywhere** in
the current code.

The deeper reason: **a single flat gossip topic has no hop structure.** In a
flood every node hears the originator directly (hop 1) — there is nothing to
discount and no loop to guard. Real hops exist only when there is *topology*:
multiple subnet topics bridged by relay nodes, where some nodes reach an
originator only *through* a bridge. That is the §5.2 federation structure.

E1 introduces that structure, minimally: per-subnet gossip topics, bridge nodes
that re-emit events across subnet boundaries with a hop appended, an
application-level dedup cache to prevent amplification, and the resulting
activation (and correctness fix) of the discount + loop guard. This is the
provenance substrate that E2 (`EvidenceAggregate` + `diversity_buckets`) and
therefore D (diversity-weighted corroboration) require.

**Non-goals:** the on-demand pull transport (E3/P1-1), the `EvidenceAggregate`
wire type (E2/§7.5), strict lowest-hop re-scoring (deferred — see §4), and any
change to the reputation math beyond the discount-exponent correction (§5).

---

## 2. Architecture

Four cooperating changes, each independently testable:

- **Transport** (`internal/transport`) — multi-topic: join the home subnet
  topic, optionally join bridged subnet topics, publish to a named topic, and
  tag each received event with its arrival subnet.
- **Node forwarding** (`internal/node`) — originator subnet stamping; a dedup
  cache; bridge re-emission across subnet boundaries; the discount-exponent fix.
- **Config** (`internal/config`) — `federation.subnet` and
  `federation.bridge_subnets`.
- **Dedup** (`internal/node`, small focused unit) — bounded, TTL'd
  seen-event set keyed by event identity.

Invariant introduced: **within one node, each unique event
`(ReporterID, IP, Reason, Timestamp)` is processed exactly once** (first-seen),
regardless of how many topology paths deliver it.

---

## 3. Topics & topology (§1 of the approved design)

- Topic name: the **home** subnet maps to the existing `DefaultTopic`
  (`federloom/events/v0`) when the subnet is `""` or `"default"` — so current
  single-subnet deployments are unchanged. A named subnet `acme` maps to
  `federloom/events/v0/acme`. Helper: `SubnetTopic(base, subnet) string`.
- Each node subscribes to its **home** subnet topic (from `federation.subnet`).
- A **bridge** node additionally subscribes to each topic in
  `federation.bridge_subnets` and relays between all the topics it is on.
- A node with an empty `bridge_subnets` is a **leaf**: home topic only, never
  re-emits.

Backward compatibility: an existing deploy with no `federation.subnet` set stays
on `federloom/events/v0` and behaves exactly as today (leaf, single topic).

---

## 4. Dedup cache

**New focused unit** (e.g. `internal/node/dedup.go`): a bounded, TTL'd set.

- Key: `dedupKey = ReporterID + "|" + IP + "|" + Reason + "|" +
  Timestamp.UTC().Format(RFC3339Nano)` — the event's identity (matches the
  fields the originator's signature covers, so a re-emitted copy has the same
  key).
- `Seen(key) bool` marks-and-reports: returns true if the key was already
  present (caller drops), false if newly inserted (caller processes).
- Bounded size (e.g. 100k entries) with TTL eviction (e.g. 10 min — longer than
  any realistic propagation delay, shorter than the reputation decay window). On
  overflow, evict oldest. Mutex-guarded (called from the single receive loop
  today, but safe for future concurrency).

**Semantics (approved):** first-seen wins. The first copy of an event to arrive
is scored/enforced and, on a bridge, re-emitted; all later copies are dropped.
Rationale: same-subnet nodes receive the direct hop-1 copy; cross-subnet nodes
receive the bridged copy (their only copy). So first-seen equals the lowest
reachable hop count in the common tree topology. Strict lowest-hop re-scoring
(when a node is reachable via two bridges at different hop counts and the
higher-hop copy arrives first) is **deliberately out of scope** — the discount
delta between adjacent hop counts is small and re-scoring an already-applied
contribution is messy. Noted as a possible future enhancement.

Both `processLocal` and `ProcessRemote` consult the cache: local events are
inserted under the node's own identity so a bridged copy that loops back is
recognised and dropped.

---

## 5. Bridge re-emission + discount/loop-guard activation

**Originator stamping** (`processLocal`): set `e.SubnetID = homeSubnet`
(currently never set) alongside the existing `e.OriginTrace = [selfID]`.

**Bridge re-emission** (`ProcessRemote`, bridge nodes only): after the event is
accepted and processed, and before returning, a bridge re-emits it to the other
subnets it bridges:
- Skip if this node is a leaf (`len(bridgeSubnets) == 0`).
- Loop guard: skip if `selfID ∈ e.OriginTrace` (already passed through us).
- Trace cap: skip if `len(e.OriginTrace) ≥ maxOriginTraceLen` (existing constant, 8).
- Otherwise build `e2 := e` with `e2.OriginTrace = append(copy, selfID)` and
  `Publish` `e2` to every bridged subnet topic **except** the arrival subnet
  (`re.Subnet`). The dedup cache on downstream nodes prevents storms.

**Discount correctness fix** (`ProcessRemote`): the current loop multiplies
`weight` by `discount` `len(OriginTrace)` times, which over-discounts by one (it
counts the originator as a hop). Change the exponent to **bridge hops =
`len(OriginTrace) - 1`**:
- direct same-subnet event (`OriginTrace = [orig]`, len 1) → **0** discounts
  (no penalty — it is your own trust domain);
- one-bridge event (len 2) → one `FederationDiscount` (×0.5);
- K-bridge event (len K+1) → `discount^K`.

This makes the discount "per subnet-crossing" (§5.2). Anchored reporters remain
exempt (their trust is explicit). The loop guard in `ProcessRemote` now
genuinely fires for bridges.

Remove the outdated "not yet active at runtime" NOTE comment once the mechanism
is live; replace with a one-line description of the per-bridge-hop discount.

---

## 6. Transport API (multi-topic)

`internal/transport`:
- `Options` gains `Subnet string` and `BridgeSubnets []string`.
- `Node` holds a `map[string]*topicHandle` (subnet → joined topic +
  subscription), keyed by subnet name (`""`/`"default"` → the base topic).
- `New` joins the home topic; if `BridgeSubnets` is non-empty, joins each of
  those too. One `readLoop` per subscription feeds the shared `events` channel.
- `ReceivedEvent` gains `Subnet string` — the subnet whose topic delivered this
  copy, so the bridge knows which topic not to echo back.
- `Publish(ctx, e, subnet)` publishes to the named subnet's topic (error if the
  node is not joined to it). The existing single-arg `Publish` is updated (its
  one caller is `processLocal`, which publishes to the home subnet).

Keep the change surgical: a single-subnet leaf (the default) joins exactly one
topic and behaves as today.

---

## 7. Config

`internal/config`, `FederationConfig` area (currently just `FederationMode` +
`FederationDiscount`):
- `federation.subnet` (`Federation.Subnet string`) — the node's home trust
  domain / subnet id. Default `""` (→ base topic). Also stamped onto published
  events as `e.SubnetID`.
- `federation.bridge_subnets` (`Federation.BridgeSubnets []string`) — subnets
  this node bridges to/from. Default empty = leaf.
- Validation: a bridge_subnets entry equal to the home subnet is dropped with a
  warning (bridging to yourself is meaningless). `FederationDiscount` already
  exists and now drives the per-hop penalty.

Document in `docs/config.md`: what a subnet is, that bridges are trust-sensitive
(§8), and that the default (no subnet) is a single flat domain.

---

## 8. Security

A bridge can drop, delay, reorder, or inject events between subnets. Bounding:
- **The stranger-block backstop (batch A) still applies end-to-end.** A bridge
  re-emitting a stranger's event cannot make a downstream node *block* — a block
  still requires anchored corroboration (`len(rec.Groups) > 0`), which a bridge
  cannot manufacture. The discount further reduces an un-anchored bridged
  event's score weight per hop.
- **Injection is bounded by trust resolution:** a bridged event is scored by the
  *originator's* resolved trust (anchored/stranger), not the bridge's. A bridge
  cannot upgrade a stranger's event to anchored.
- **Defederation is the containment** (§5.2): stop bridging a bad subnet, or add
  its peers to the blocked-peers list. Per-subnet isolation is the Sybil answer
  at the topology level.
- **Loop/amplification safety:** the loop guard + dedup cache + trace cap
  jointly prevent a re-emission storm or A↔B double-processing.

State these in the design doc's security section and in `docs/threat-model.md`.

---

## 9. Testing

- **Dedup unit** (`internal/node/dedup_test.go`): first insert returns
  not-seen; second returns seen; distinct keys independent; TTL eviction; bound
  eviction.
- **Discount exponent unit** (extend node or reputation tests): assert
  `len(OriginTrace)==1` → weight unchanged; len 2 → ×discount once; len 3 →
  ×discount². Anchored → unchanged regardless of trace length.
- **Adversarial topology integration** (`test/integration/` or
  `test/adversarial/`): a 3-node graph — node A in subnet `a`, a bridge in
  {`a`,`b`}, node C in subnet `b`. Assert: A's event reaches C with
  `OriginTrace == [A, bridge]` and its weight discounted once; the bridge does
  **not** re-emit a copy bearing its own id (loop guard); when C is reachable via
  two bridges, C scores the event **once** (dedup), not twice; a leaf never
  re-emits.
- **Backward-compat:** a node with no `federation.subnet`/`bridge_subnets`
  joins the base topic and the existing gossip/adversarial suites still pass.
- **Full gate:** `make build test adversarial`, `go vet`, `gofmt -l` clean.

---

## 10. Out of scope / follow-ups

- `EvidenceAggregate` + `diversity_buckets` (E2/§7.5) — consumes this
  provenance; unblocks D.
- On-demand pull transport (E3/P1-1).
- Strict lowest-hop re-scoring (§4) — deferred enhancement.
- Dynamic subnet discovery/membership — bridges and subnets are static config
  here; discovery is a later concern.
- After merge, update spec §12a traceability: §5.2 federation
  import/discount/origin-trace → PARTIAL becomes "origin-trace + hop-discount
  DONE (subnet-bridge); evidence import PLANNED (E2)".

## 11. Acceptance

An event originated in subnet `a` and bridged into subnet `b` arrives at a `b`
node with a multi-entry `OriginTrace` and a per-bridge-hop-discounted weight; the
loop guard prevents re-emission cycles; the dedup cache guarantees each unique
event is scored once across all delivery paths; a same-subnet direct event is
**not** discounted (exponent fix); and a default (no-subnet) deployment behaves
exactly as before. The discount and loop guard, inert today, are demonstrably
active under a bridged topology.
