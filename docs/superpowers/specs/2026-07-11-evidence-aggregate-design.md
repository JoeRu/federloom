# EvidenceAggregate + Scale-Free Local Recompute (Roadmap Step 2 / E2)

**Status:** Design approved 2026-07-11
**Source:** [docs/roadmap.md](../../roadmap.md) Step 2 — item A1; resolves B4
(E3's MVP-approved simplifications). Spec §7.5 (evidence aggregate), §8
(local recomputation from evidence — core mechanic), §5.2 (federation
import, option b), §4.2 (diversity carried across the import).
**Prerequisite:** E3 (federated query) + Step 1 (repquery hardening) merged.
**Unblocks:** D (diversity-weighted corroboration, roadmap Step 3) and
materialise-on-verdict (Step 4).

---

## 1. Problem

E3's federated query answers a raw `ScoreEntry` — a score computed in the
*aggregator's* trust domain. Merging foreign scores (max-score combiner) is
exactly what §5.2 warns against; both were shipped as ⚠-revisit MVP
simplifications (E3 design §4/§6; roadmap B4). §8 states the intended
mechanic: the score is **never an imported foreign value** — every node
recombines evidence through **its own rule engine**.

E2 replaces the query answer with the §7.5 `EvidenceAggregate` and gives the
consumer a scale-free local recompute that reuses the reputation engine's
own accumulation math.

## 2. Decisions made during brainstorming (user-selected)

1. **Attestation = trusted-aggregator word.** The authenticated libp2p
   channel + explicit aggregator configuration is the attestation (same
   trust model as anchors). A lying aggregator = a compromised anchor;
   containment is defederation. No bucket cryptography. Consequence:
   cross-aggregator dedup is impossible, so the merge must be conservative.
2. **Merge = max of locally-recomputed scores** + union of scenarios.
   Never double-counts under unknown reporter overlap; every input is on
   the consumer's own scale before comparison.
3. **Clean protocol break.** `/federloom/repquery/v2` *replaces* v1 — no
   dual registration, no fallback, no legacy carry. Rationale: the project
   has no external deployments; not even the SwarmGuard nodes configure
   `federation_aggregators` yet. Knock-on: `proto.ScoreEntry` drops out of
   the query path and reverts to reserved/unused — it joins `port_class`
   in the roadmap C1 wire-cleanup bundle (removal at the events-v1 bump).

## 3. Scope

**In:** the `EvidenceAggregate` wire type; protocol bump to v2; aggregator-
side projection; the pure-accumulator refactor of the reputation engine;
consumer-side recompute + merge; cache/resolver integration; docs + spec
traceability; adversarial scenario.
**Out:** ASN/region bucket dimensions and diversity *weighting* in scoring
(Step 3 / D — the bucket map is deliberately generic so D adds keys without
a wire change); materialise-on-verdict (Step 4); disputes (Step 5);
`ScoreEntry`/`port_class` removal (Step 6); any gossip-path change (evidence
import rides the query path only); per-aggregator trust weights (YAGNI —
the existing `Trust.FederationDiscount` is the import discount).

---

## 4. Wire type (`pkg/proto`, additive)

```go
// EvidenceAggregate is the federated import type (spec §7.5): what subnets
// share and every consumer recomputes locally (§8). Lighter than raw events,
// richer than an opaque score. Carries NO reporter identity — only distinct
// counts per bucket dimension.
type EvidenceAggregate struct {
	IP               string         `json:"ip"`                // IPv4 single / IPv6 prefix-normalized
	Scenarios        []string       `json:"scenarios"`         // distinct reason codes observed (§7.1)
	WindowFirst      time.Time      `json:"window_first"`      // evidence window start
	WindowLast       time.Time      `json:"window_last"`       // zero = "not found" sentinel
	DiversityBuckets map[string]int `json:"diversity_buckets"` // dimension -> distinct reporter count; MVP: "groups", "reporters"; D adds "asn"/"region"
	StrangersPresent bool           `json:"strangers_present"` // un-anchored reporters contributed
	EvidenceWeight   float64        `json:"evidence_weight"`   // aggregator's source weight; consumer clamps to [0,1]
}
```

**Protocol:** `repquery.ProtocolID` becomes `"/federloom/repquery/v2"`;
the responder answers `EvidenceAggregate` (one `RepQuery` → one aggregate).
`RepQuery` unchanged. Step 1's authorization (anchored ∧ not blocked, fail
closed) and stream deadline are untouched. The v1 answer path is deleted,
not deprecated.

## 5. Aggregator-side projection (`internal/repquery`)

`AggregateFromRecord(ip string, r store.ScoreRecord) proto.EvidenceAggregate`
— a pure projection of the local record:
- `Scenarios` = `r.Reasons` (distinct reason codes).
- `WindowFirst/Last` = `r.FirstSeen/LastSeen` (zero `LastSeen` → zero
  `WindowLast` = not-found sentinel, same style as today).
- `DiversityBuckets` = `{"groups": len(r.Groups), "reporters": len(r.ReporterIDs)}`.
- `StrangersPresent` = `r.StrangerSeen`.
- `EvidenceWeight` = `1.0` (constant for now; per-aggregator weights YAGNI).

Privacy: counts only — `Groups`/`ReporterIDs` contents never leave the node
(§7.5 "never reporter identity"; consistent with E3's tracking-field rule).

## 6. Engine refactor — the pure accumulator (`internal/reputation`)

Extract `Record`'s accumulation math into a pure function over a
`ScoreRecord` value (indicative shape — the plan pins exact signatures):

```go
// Observation is one scoring input (native event or synthetic evidence vote).
type Observation struct { Reason, ReporterID, Group string; Trust float64; Anchored bool }

// Accumulate applies obs to rec (decay-adjusted at now) and returns the new
// record. Pure: no store access. Record() becomes load -> Accumulate -> save.
func Accumulate(rec store.ScoreRecord, obs Observation, now time.Time, halfLife time.Duration, strangerCap float64) store.ScoreRecord
```

**Equivalence requirement:** `Record`'s observable behavior is byte-identical
after the refactor — existing engine + adversarial tests must pass unchanged,
plus one explicit equivalence test (same sequence via `Record` vs. manual
`Accumulate` folds yields the same stored record).

## 7. Consumer recompute (`internal/repquery`)

`RecordFromEvidence(ev proto.EvidenceAggregate, now time.Time, p Params) store.ScoreRecord`
where `Params` carries the consumer's own `halfLife`, `strangerCap`,
`FederationDiscount`, and reason-weight lookup. Pure function:

1. Clamp `ev.EvidenceWeight` to `[0,1]`; effective trust
   `T = weight × FederationDiscount`.
2. Pick the **max-weight scenario under the consumer's local weight table**
   as the vote reason (the local table governs — §8).
3. Fold through `Accumulate` over an empty record: one anchored-style vote
   per counted group (`ev.DiversityBuckets["groups"]`), synthetic group
   labels (`fed:g1..gN`) that exist **only inside the fold**; plus one
   stranger vote if `ev.StrangersPresent` (subject to the consumer's own
   stranger cap).
4. Apply decay from `ev.WindowLast` to `now` with the consumer's half-life.
5. Result: `Reasons` = union of `ev.Scenarios`; `FirstSeen/LastSeen` from
   the window; **`Groups`, `ReporterIDs`, `StrangerSeen` empty/false** in
   the returned record.

**Critical invariant:** the returned record's `Groups` is ALWAYS empty. A
federated answer must never manufacture anchored corroboration toward the
local block backstop (batch A: block requires `len(rec.Groups) > 0`). The
synthetic labels never leave the fold. `WindowLast` zero → empty record
(not-found passthrough).

## 8. Querier / resolver / cache

- Querier decodes `EvidenceAggregate` from each aggregator, calls
  `RecordFromEvidence` per answer, merges by **max recomputed `Score`**,
  `Reasons` = union of scenario lists across answers.
- The cache stores the merged **recomputed `ScoreRecord`** (bound, TTL,
  negative-TTL, singleflight machinery from Step 1 unchanged — only the
  cached value type changes).
- Resolver/DNSBL/score-API are untouched: they already consume
  `store.ScoreRecord`. `EntryFromRecord`/`RecordFromEntry` (the
  `ScoreEntry` conversions) are deleted with the v1 answer path.
- E3's hardening guarantees carry over verbatim: stream deadline in `ask`,
  `qctx.Done()` select in `fanout`, empty-`federation_aggregators` = today's
  local-only behavior byte-for-byte.

## 9. Security

- **Read-only preserved:** recompute is pure; no store writes, no
  enforcement writes (materialise is Step 4).
- **Lists are aids:** the consumer's weight table, stranger cap, discount,
  half-life, and threshold govern the final number; the aggregator supplies
  evidence, never a verdict (§2 Leitprinzip 8).
- **Bounded inflation:** an aggregator claiming absurd buckets ("500
  groups") is bounded by the consumer's own corroboration curve and
  logistic accumulation; the answer stays advisory (DNSBL/API only); the
  returned `Groups` stays empty; containment = defederation. Adversarial
  scenario required (see §10).
- **Privacy:** counts only on the wire; no hashing-as-pseudonymisation
  introduced (spec §9).
- Step 1's responder authorization and DoS bounds are unchanged.

## 10. Testing

- **Engine equivalence:** existing reputation + adversarial suites pass
  unchanged; explicit `Record`-vs-`Accumulate` equivalence test.
- **Recompute unit table:** known aggregates → expected scores under
  default params; stranger-only evidence respects the local cap; decay
  applied from `WindowLast`; zero-window → empty record; `Groups` empty in
  every output.
- **Merge:** two aggregators, different evidence → max recomputed score
  wins, scenarios unioned.
- **Integration (two-host v2):** aggregator B holds a scored IP; consumer A
  fetches the aggregate over `/federloom/repquery/v2` and its DNSBL/API
  answer reflects A's own recompute. Node wiring test updated.
- **Adversarial:** an inflated-bucket aggregator (e.g. 500 groups, max
  scenario) yields a bounded score, never populates `Groups`, and cannot
  trip the anchored-corroboration block backstop.
- **Full gate:** build, vet, gofmt, unit, `-race` on repquery/reputation,
  adversarial, integration.

## 11. Docs (same PR)

- `docs/config.md`: the query answer is now evidence, recomputed locally;
  `FederationDiscount` doubles as the evidence-import discount.
- `docs/spec.md` §12a: §7.5 → DONE (exchanged as the v2 query answer);
  §5.2 evidence import → DONE via query path (gossip-side import remains
  out of scope); §7.2 `ScoreEntry` → reverts to RESERVED, slated for
  removal in the C1 wire cleanup.
- `docs/roadmap.md`: Step 2 ✅, B4 ✅, C1 row gains `ScoreEntry`.
- `docs/architecture.md`: one line — the query read path now transports
  evidence, not scores.

## 12. Acceptance

A consumer that locally knows nothing about IP X, with aggregator B
configured, answers a DNSBL/API lookup for X with a score **computed by its
own rules** from B's `EvidenceAggregate` (own weight table, own caps, own
half-life, own discount), merged across aggregators by max-of-recomputed;
the returned record never carries `Groups`; behavior with no aggregators is
byte-for-byte unchanged; `/federloom/repquery/v1` no longer exists; all
suites including the new adversarial scenario pass.
