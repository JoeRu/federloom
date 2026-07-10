# FederLoom Roadmap

**Status:** 2026-07-10 · supersedes spec §13 "Nächste Schritte" as the
sequencing document. Ground truth for *what is live* remains the spec §12a
traceability table; ground truth for *what was wrong* is
[critics-and-suggestions.md](critics-and-suggestions.md). This file orders
what is still open into a dependency-correct sequence and persists the
review-discovered follow-ups that previously lived only in session scratch.

---

## Part 1 — Review of work done (the 2026-07 remediation wave)

Everything below shipped to `main` between 2026-07-07 and 2026-07-10, each as
brainstorm → spec → plan → subagent-driven implementation → per-task review →
whole-branch final review → merge. Specs/plans in `docs/superpowers/`.

| Wave | Critique items | What shipped | Notable review catches |
|---|---|---|---|
| **Batch A** — security hardening | P0-1…P0-5 | Anchored-corroboration block backstop (strangers can `watch`, never `block`), remote burst-counter hardening, never-block defaults widened to spec §10, adversarial CI now covers the enforcement path, DNSBL bound to private interface | Never-block/test conflict (8.8.8.8 as control IP) |
| **Batch B** — doc/spec truth-up | P2-1…P2-4, P3-1…P3-3 | Wire-contract deprecation comments, spec §12a traceability table, README join path, architecture caveats, API-auth docs | — |
| **Stranger-block guarantee** | P0-1 follow-up | Lint + invariant test that no config can let an unanchored stranger reach block threshold | Strict `>` vs `>=` boundary at the score cap |
| **C — IPv6 `/64`** | P1-4 | Prefix normalization (`internal/netutil`), split-reputation prevention, ipset migration | Out-of-range prefix warning, whitelist prefix-width caveat |
| **E1 — subnet-bridge forwarding** | P1-5 | Per-subnet gossip topics, bridge re-emission with hop-append, dedup cache, per-bridge-hop discount (exponent fix) | **C1 (Critical, whole-branch review):** the batch-A spoof guard dropped every bridged event — feature was inert; fixed by accepting signed relayed events. I1: one-directional relay. |
| **E3 — federated on-demand query** | P1-1 (read path) | `internal/repquery`: first libp2p request/response protocol (`/federloom/repquery/v1`), querier + TTL cache, Resolver (local-then-federated `GetScore`) behind DNSBL + per-IP score API; off by default | **Two bugs in the plan's own reference code:** Query could hang past its timeout (no stream deadline); score-0 known-clean answers collapsed into the not-found sentinel. Plus: node-wiring guard initially untested (E1-lesson), responder slowloris deadline added pre-merge. |

**Process observation worth keeping:** in both E1 and E3 the per-task reviews
passed while the deeper review layer (whole-branch, or a rigorous per-task
reviewer on novel code) caught Critical/Important defects — including bugs
transcribed faithfully from the plan itself. The multi-layer review is not
overhead; it is where the real catches happen. Keep it for everything touching
`internal/reputation`, `internal/trust`, `internal/enforce`, transport, and
wire types.

**Resolved critique status:** all P0s closed; all P2/P3 doc-drift closed;
P1-4 closed; P1-5 closed; P1-1 partially closed (pull *read* path live;
DHT/bloom + materialise-on-verdict remain). Open: P1-2 (diversity), P1-3
(disputes), P1-6 (applicability), and the scaling hardening of §11.

---

## Part 2 — Open issues (consolidated, deduplicated)

### A. Design promises not yet built (spec §12a `PLANNED`)

| # | Item | Spec | Critique |
|---|---|---|---|
| A1 | `EvidenceAggregate` federated import + scale-free local recompute + attested `diversity_buckets` | §5.2, §7.5, §8 | P1-1 core |
| A2 | Diversity-weighted corroboration (ASN/geo buckets) | §4.2 | P1-2 |
| A3 | Dispute / anti-trust votes (the `Disputes` field is on the wire but never populated) | §4.4 | P1-3 |
| A4 | Applicability weighting / system profile (SBOM matchmaker) | §4.5, §7.6 | P1-6 |
| A5 | Materialise-on-verdict: a block-worthy *federated* verdict for an IP that contacted you pushes into ipset (O(1) path) — explicitly deferred from E3 until evidence is scale-free | E3 design §8 | P1-1 |
| A6 | Federation-scale hardening: bloom pre-filter for the federated path, DHT content routing, batch queries | §11.3/§11.4 | P1-1 |
| A7 | Resource budget + load shedding (CPU/bandwidth budget, graceful degradation) | §11.5 | federation-roadmap Phase 4, never built |

### B. Review-discovered technical debt (from E1/E3 final reviews — previously scratch-only, now durable here)

| # | Item | Severity | Origin |
|---|---|---|---|
| B1 | **Responder answers *any* peer**: `/federloom/repquery/v1` is registered on the shared transport host with no aggregator/subnet authorization. Enabling `federation_aggregators` (client role) silently makes the node an unauthenticated reputation oracle for the swarm. Stream deadline (shipped) bounds slowloris, but authorization is required **before the protocol is exposed beyond explicitly trusted peers**. | Important | E3 whole-branch review |
| B2 | `OriginTrace` is unsigned — a malicious relay can under-report hop count to reduce the federation discount. Bounded by the stranger-block backstop + dedup + decay. | Minor (advisory) | E1 final re-review |
| B3 | Querier cache is unbounded (grows per distinct IP, incl. negatives); no in-flight de-dup (concurrent misses for the same IP each fan out). | Minor | E3 Task-4 review |
| B4 | E3 MVP-approved simplifications to *replace*, not patch: raw cross-domain `ScoreEntry` merge (foreign score scale, §5.2 warning) and max-score combiner. Resolved by design when A1 lands. | Accepted-MVP | E3 design §4/§6 |
| B5 | Small polish: responder `Close()` vs `Reset()` on decode error; `SetDeadline` error swallowed; redundant explicit `Connect`; E1 strict lowest-hop re-scoring; E1 echo-suppression only single-bridge tested. | Trivial | various reviews |

### C. Wire/protocol housekeeping

| # | Item |
|---|---|
| C1 | `port_class` is deprecated-retained in `pkg/proto` (P2-1). Removal is a breaking wire change — bundle into the next protocol version bump (`federloom/events/v1`), ideally together with signing `OriginTrace` (B2), so the network pays for one migration, not two. |
| C2 | Spec §13 "Nächste Schritte" is stale again (items 5, 8, 10, 11, 15, 17 are done or superseded). Point it at this roadmap. |

---

## Part 3 — The sequence

Ordering rationale: **(1)** small security debt before new features; **(2)** A1
(`EvidenceAggregate`) is the keystone — A2, A5, and the B4 replacements all
depend on it, so it goes early; **(3)** research-grade features (A2–A4) after
their data substrate exists; **(4)** scale hardening last, when there is
something to scale.

### Step 1 — Repquery hardening (small, security) → B1, B3, B5
Add responder authorization: answer `/federloom/repquery/v1` only for peers in
a configured allow-set (default: the node's own `federation_aggregators` plus
explicitly listed peers; empty ⇒ responder not registered — mirrors the
querier gate). Bound the querier cache (LRU or size cap) and add in-flight
de-dup (singleflight). Fold in the B5 trivia. Contained, no design debate,
closes the one Important finding on `main`.

### Step 2 — E2: `EvidenceAggregate` + scale-free recompute → A1, resolves B4
The keystone. New wire type (§7.5): per-IP evidence summary (reporter counts,
attested `diversity_buckets`, first/last seen, reason histogram) instead of a
domain-scaled score. The repquery answer carries it; the consumer recomputes
the score under *its own* rules (§8) — killing the cross-domain score-scale
problem and the max-score combiner in one move. Needs its own brainstorm
(bucket attestation model is the hard part: who vouches that "3 distinct ASNs"
is true?).

### Step 3 — D: diversity-weighted corroboration → A2
Consumes E2's `diversity_buckets`. Corroboration counts distinct ASN/geo
buckets, not raw reporters — the actual Sybil-resistance upgrade (§4.2).
Open question from the critique still to decide at brainstorm: offline ASN
table (IPtoASN bundled at build) vs. live lookups (privacy leak) vs.
bucket-by-/16 heuristic (no dependency).

### Step 4 — Materialise-on-verdict → A5
With scale-free evidence (Step 2) + diversity weighting (Step 3), a federated
verdict is finally trustworthy enough to *push*: block-worthy answer for an IP
that contacted you → ipset (subject to never-block/whitelist + operator
threshold + the stranger-block backstop analogue for federated evidence).
Completes E3's "pull discovers, push enforces" synthesis. Security-critical —
full adversarial scenarios required.

### Step 5 — Disputes / anti-trust votes → A3
Populate the existing `Disputes` wire field: signed "this IP is wrongly
listed" votes, weighted by trust, accelerating decay (§4.4). Natural after
Step 4, because materialised federated blocks are exactly what disputes must
be able to undo. Keeps invariant 1 (lists are aids): disputes are the
network-level override to complement the local one.

### Step 6 — Wire v1 bump → C1, B2
One breaking migration bundling: `port_class` removal, signed `OriginTrace`
(hop-count integrity), and any E2 field learnings. Dual-listen `v0`/`v1`
transition window per `.claude/skills/wire-protocol`.

### Step 7 — Scale & resilience → A6, A7
Bloom pre-filter for the federated read path, batch/multi-IP queries, DHT
content routing if aggregator lists prove too static; resource budget + load
shedding (§11.5). Driven by real deployment telemetry from the SwarmGuard
environment, not speculation — do this when measurements say so.

### Parked (no sequence position, revisit on demand)
- A4 applicability weighting / system profile (§4.5/§7.6): valuable, but the
  weakest cost/benefit of the open items; needs SBOM infrastructure. Revisit
  after Step 5 with real multi-role deployment data.
- Dynamic subnet discovery/membership (E1 follow-up): bridges stay static
  config until federation topology demonstrably needs discovery.
- Strict lowest-hop re-scoring (E1 §4 deferral): the discount delta between
  adjacent hop counts is small; not worth re-scoring machinery yet.

---

## Sequencing at a glance

```
Step 1  repquery hardening (B1,B3,B5)      [small, closes Important finding]
Step 2  E2 EvidenceAggregate (A1, →B4)     [keystone; own brainstorm]
Step 3  D  diversity corroboration (A2)    [needs Step 2]
Step 4  materialise-on-verdict (A5)        [needs Steps 2+3; security-critical]
Step 5  disputes (A3)                      [complements Step 4]
Step 6  wire v1 bump (C1,B2)               [one migration for all breaks]
Step 7  scale hardening (A6,A7)            [telemetry-driven]
parked  A4 applicability, subnet discovery, lowest-hop re-scoring
```

Each step follows the established loop: brainstorm → spec → plan →
subagent-driven implementation → reviews → merge to `main` + push. Adversarial
suite updates are mandatory for Steps 2–5 (they all touch reputation/trust).
