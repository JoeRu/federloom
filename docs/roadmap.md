# FederLoom Roadmap

**Status:** 2026-07-10 · supersedes spec §13 "Next Steps" as the
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
| A1 | `EvidenceAggregate` federated import + scale-free local recompute + attested `diversity_buckets`. ✅ resolved | §5.2, §7.5, §8 | P1-1 core |
| A2 | Diversity-weighted corroboration (ASN/geo buckets) ✅ resolved — subnet-diversity weighting (score-only; ASN/geo later) | §4.2 | P1-2 |
| A3 | Dispute / anti-trust votes ✅ resolved — federated shared-vote, diversity-weighted, unblock-federated-only | §4.4 | P1-3 |
| A4 | Applicability weighting / system profile (SBOM matchmaker) | §4.5, §7.6 | P1-6 |
| A5 | Materialise-on-verdict: a block-worthy *federated* verdict for an IP that contacted you pushes into ipset (O(1) path) — explicitly deferred from E3 until evidence is scale-free ✅ resolved — diversity-gated, TTL-bounded, opt-in | E3 design §8 | P1-1 |
| A6 | Federation-scale hardening: bloom pre-filter for the federated path, DHT content routing, batch queries | §11.3/§11.4 | P1-1 |
| A7 | Resource budget + load shedding (CPU/bandwidth budget, graceful degradation) ✅ resolved — load shedding 2026-07-17 | §11.5 | federation-roadmap Phase 4, never built |

### B. Review-discovered technical debt (from E1/E3 final reviews — previously scratch-only, now durable here)

| # | Item | Severity | Origin |
|---|---|---|---|
| B1 | **Responder answers *any* peer**: `/federloom/repquery/v1` is registered on the shared transport host with no aggregator/subnet authorization. Enabling `federation_aggregators` (client role) silently makes the node an unauthenticated reputation oracle for the swarm. Stream deadline (shipped) bounds slowloris, but authorization is required **before the protocol is exposed beyond explicitly trusted peers**. ✅ resolved — trust-store authz, fail closed | Important | E3 whole-branch review |
| B2 | `OriginTrace` is unsigned — a malicious relay can under-report hop count to reduce the federation discount. Bounded by the stranger-block backstop + dedup + decay. ✅ resolved — wire v2 2026-07-16 | Minor (advisory) | E1 final re-review |
| B3 | Querier cache is unbounded (grows per distinct IP, incl. negatives); no in-flight de-dup (concurrent misses for the same IP each fan out). ✅ resolved — bounded cache + singleflight | Minor | E3 Task-4 review |
| B4 | E3 MVP-approved simplifications to *replace*, not patch: raw cross-domain `ScoreEntry` merge (foreign score scale, §5.2 warning) and max-score combiner. ✅ resolved — replaced by EvidenceAggregate + local recompute | Accepted-MVP | E3 design §4/§6 |
| B5 | Small polish: responder `Close()` vs `Reset()` on decode error; `SetDeadline` error swallowed; redundant explicit `Connect`; E1 strict lowest-hop re-scoring; E1 echo-suppression only single-bridge tested. ✅ resolved — Reset/deadline-log/peerstore-seeding; multi-bridge echo test added; lowest-hop re-scoring stays parked | Trivial | various reviews |
| B6 | `RecordFromEvidence` (E2) does not cap the `Scenarios` slice / `DiversityBuckets` map size, unlike the `groups` fold-cap (`maxEvidenceFolds=64`) — a lying aggregator can force O(n) alloc + per-IP cache-memory amplification. Bounded by the stream deadline + defederation (matches the trusted-aggregator model). Cap after max-weight scenario selection when hardening the gossip-side import. | Low | E2 whole-branch review |
| B7 | `e.SubnetID` (and `OriginTrace`, cf. B2) are NOT covered by the event signature (`identity.eventMessage` signs IP\|Reason\|Timestamp\|ReporterID) — so D's "bridge-launder resistant" diversity keying is not cryptographically enforced: a relay can rewrite `SubnetID` and `VerifyEventSig` still passes. Exploitability bounded — a bridge can only DEFEAT damping (return to pre-feature full-weight scoring), never inflate past the baseline, and dedup drops same-content replays. ✅ resolved — wire v2 2026-07-16 | Medium | D whole-branch review |
| B8 | `RecordFromEvidence` subnet-cap off-by-one: the shared `fed-repeat` synthetic subnet's first fold counts as a new subnet, so `fullVotes+1` votes are full-weight when `groups>subnets`. Negligible under logistic saturation; slightly loosens the E2 subnet-cap. Tighten if the federated fold is revisited. | Low | D whole-branch review |
| B9 | ipset/nftables `Start` does not migrate a pre-existing no-timeout set to a timeout-capable one on in-place upgrade (create ... timeout 0 -exist no-ops on an existing set), so materialise `BlockFor` is rejected until the set is recreated. Fails safe (logged, no block). Add an entry-preserving migration (save/restore/swap) — deploy-time-testable, not fake-run-testable. | Medium | Step 4 whole-branch review |
| B10 | Dispute→unblock TOCTOU: `materialiseFederated` releases `matMu` between the `disputed[ip]` check and the `BlockFor`+`materialised[ip]` set, so a concurrent dispute crossing the floor can let one federated block land that a later dispute vote clears (else it self-expires at TTL). Over-block only (safe direction), opt-in path. Make the check-block-record sequence atomic if exact suppression timing matters. | Low | Step 5 whole-branch review |
| B11 | `node.disputed` (re-materialise suppression set) is never GC'd — an IP diversely disputed once is suppressed from re-materialisation until node restart, even if it later turns genuinely bad. In-memory only, safe direction, needs ≥floor distinct anchored subnets to enter. Add a TTL/GC (mirror the materialised-block TTL) when the dispute path is revisited. | Low | Step 5 whole-branch review |

### C. Wire/protocol housekeeping

| # | Item |
|---|---|
| C1 | `port_class` and `ScoreEntry` are deprecated-retained in `pkg/proto` (P2-1). ✅ resolved — wire v2 2026-07-16 (removed `port_class` and `ScoreEntry`, bundle with signed `SubnetID` B7 + hop-count discount B2 in single migration) |
| C2 | Spec §13 "Next Steps" is stale again (items 5, 8, 10, 11, 15, 17 are done or superseded). Point it at this roadmap. ✅ done 2026-07-10 (superseded-note added; spec translated to English) |

---

## Part 3 — The sequence

Ordering rationale: **(1)** small security debt before new features; **(2)** A1
(`EvidenceAggregate`) is the keystone — A2, A5, and the B4 replacements all
depend on it, so it goes early; **(3)** research-grade features (A2–A4) after
their data substrate exists; **(4)** scale hardening last, when there is
something to scale.

### Step 1 — Repquery hardening (small, security) → B1, B3, B5 ✅ done 2026-07-11
As built (design 2026-07-10; the allow-list sketch originally here was
superseded during brainstorming): responder authorization is **trust-store
based** — answer `/federloom/repquery/v1` iff the peer is anchored and not
blocked (fail closed, `Reset` before reading a byte); the serve role is
**always-on when federated** (decoupled from the client role, fixing the
"pure aggregator serves nothing" hole found during design; zero new config,
defederation is the per-peer off switch). Querier cache bounded (65536,
evict expired→oldest) + singleflight de-dup + peerstore seeding replacing
the per-ask `Connect`. B5 folded in; multi-bridge echo + adversarial
Sybil-querier tests added.

### Step 2 — E2: `EvidenceAggregate` + scale-free recompute → A1, resolves B4 ✅ done 2026-07-12
The keystone. New wire type (§7.5): per-IP evidence summary (reporter counts,
attested `diversity_buckets`, first/last seen, reason histogram) instead of a
domain-scaled score. The repquery answer carries it; the consumer recomputes
the score under *its own* rules (§8) — killing the cross-domain score-scale
problem and the max-score combiner in one move. Needs its own brainstorm
(bucket attestation model is the hard part: who vouches that "3 distinct ASNs"
is true?).

### Step 3 — D  diversity-weighted corroboration → A2 ✅ done 2026-07-12
Consumes E2's `diversity_buckets`. Corroboration counts distinct ASN/geo
buckets, not raw reporters — the actual Sybil-resistance upgrade (§4.2).
Open question from the critique still to decide at brainstorm: offline ASN
table (IPtoASN bundled at build) vs. live lookups (privacy leak) vs.
bucket-by-/16 heuristic (no dependency).

### Step 4 — Materialise-on-verdict → A5 ✅ done 2026-07-13
With scale-free evidence (Step 2) + diversity weighting (Step 3), a federated
verdict is finally trustworthy enough to *push*: block-worthy answer for an IP
that contacted you → ipset (subject to never-block/whitelist + operator
threshold + the stranger-block backstop analogue for federated evidence).
Completes E3's "pull discovers, push enforces" synthesis. Security-critical —
full adversarial scenarios required.

### Step 5 — Disputes / anti-trust votes → A3 ✅ done 2026-07-14
Populate the existing `Disputes` wire field: signed "this IP is wrongly
listed" votes, weighted by trust, accelerating decay (§4.4). Natural after
Step 4, because materialised federated blocks are exactly what disputes must
be able to undo. Keeps invariant 1 (lists are aids): disputes are the
network-level override to complement the local one.

### Step 6 — Wire v2 bump → C1, B2, B7 ✅ done 2026-07-16
One breaking migration bundling: `port_class` and `ScoreEntry` removal, signed
`SubnetID` (federated diversity integrity, B7), and signed-subnet federation
discount keying (B2) instead of per-hop. Hop count no longer affects scoring;
`OriginTrace` retained for feedback-loop guard, trace-cap, dedup. Hard cutover:
no v1↔v2 compatibility (per `.claude/skills/wire-protocol`).

### Step 7 — Scale & resilience → A6, A7 — partially done
A7 (resource budget + load shedding, §11.5) ✅ resolved 2026-07-17: a
processing-rate `Governor` (`internal/resources`) sheds network-contribution
work — remote gossip scoring, bridge re-emission, on-demand federated
queries — above `resources.max_events_per_sec`, while local protection (own
ingest → score → enforce) is never shed. Off by default (`0`). Adversarial
coverage: `test/adversarial/load_shedding_test.go` proves a gossip flood trips
shed mode without ever fabricating a block. TODO (follow-up, deliberately
deferred from this branch): document `resources.max_events_per_sec` in
`deploy/examples/*.yaml`.

A6 (bloom pre-filter for the federated read path, batch/multi-IP queries, DHT
content routing if aggregator lists prove too static) remains PLANNED — driven
by real deployment telemetry from the SwarmGuard environment, not
speculation — do this when measurements say so.

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
Step 7  scale hardening (A6,A7)            [A7 done 2026-07-17; A6 telemetry-driven]
parked  A4 applicability, subnet discovery, lowest-hop re-scoring
```

Each step follows the established loop: brainstorm → spec → plan →
subagent-driven implementation → reviews → merge to `main` + push. Adversarial
suite updates are mandatory for Steps 2–5 (they all touch reputation/trust).
