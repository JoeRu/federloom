# Subnet-Diversity-Weighted Corroboration (Roadmap Step 3 / D)

**Status:** Design approved 2026-07-12
**Source:** [docs/roadmap.md](../../roadmap.md) Step 3 — item A2 (critique P1-2).
Spec §4.2 (diversity-weighted corroboration), §8 (effective weight), §7.5
(diversity_buckets from origin_trace/subnet_id).
**Prerequisite:** E1 (subnet_id / origin_trace on events) + E2
(EvidenceAggregate + `RecordFromEvidence`) merged.
**Unblocks:** nothing downstream depends on it; it is the §4.2 payoff and
hardens the E2 inflated-bucket vector.

---

## 1. Problem

Corroboration today weights every report equally: N reports raise the score
regardless of whether they came from one operator or N independent ones. §4.2
requires the opposite — "10 reports from one source ≈ 1 vote; 10 from 10
sources = a genuine signal" — because forging *breadth* requires an attacker
to hold infrastructure across many independent domains, while forging *volume*
from one domain is cheap. D makes the score reflect source diversity.

## 2. Decisions made during brainstorming (user-selected)

1. **Diversity substrate = federation subnet** (from E1's `subnet_id` /
   `origin_trace`), not geo-ASN. Zero external data, no reporter
   geolocation (no new privacy/GDPR surface), no bundle staleness — and it
   is exactly the substrate §7.5 names. ASN/region stay as possible future
   bucket dimensions; the ASN-data-source question is deferred, not answered.
2. **Diversity modifies the advisory SCORE only.** The block gate stays
   anchored-Person corroboration (`len(Groups) > 0`) — unchanged. Subnets
   and strangers still can never force a block (Leitprinzip 8; the batch-A
   P0-1 backstop is untouched). This also keeps a subnet (cheaper to spin up
   than an anchored Person key) out of the block path.
3. **Damping = first-from-subnet full, repeats damped.** Track the set of
   distinct subnets that reported an IP; the first report from a *new*
   subnet gets full contribution, a repeat from an already-counted subnet is
   scaled by a small diversity factor. Minimal state (a subnet set on the
   record, mirroring the existing stranger bucket); the federated path folds
   `diversity_buckets["subnets"]` as that many fresh votes.

## 3. Scope

**In:** a `SubnetsSeen` set on the record; an `Observation.Subnet` field and
the diversity factor in `Accumulate`; native wiring from `e.SubnetID`;
`subnets` bucket in `AggregateFromRecord`; subnet-capped folds in
`RecordFromEvidence`; one config knob; tests + docs.
**Out:** ASN/region diversity dimensions and any external geolocation data
(future); changing the block gate or `min_corroboration` semantics; per-subnet
histograms (the harmonic/hard-cap mechanics were rejected); gossip-side
evidence import (still PLANNED); the B6 Scenarios/bucket-size cap
(independent follow-up).

---

## 4. Native mechanic (`internal/reputation`)

`store.ScoreRecord` gains:
```go
	SubnetsSeen []string `json:"subnets_seen,omitempty"` // distinct subnets that reported this IP (diversity, §4.2)
```
It is TTL'd with the record like the other fields; it holds subnet ids
locally and is NEVER shipped as names (only its length goes on the wire, §5).

`reputation.Observation` gains a `Subnet string` field.

In `Accumulate`, the contribution line becomes diversity-weighted. Insert
before the existing `contrib :=` computation:
```go
	firstFromSubnet := obs.Subnet != "" && !containsString(rec.SubnetsSeen, obs.Subnet)
	divFactor := 1.0
	if obs.Subnet != "" && !firstFromSubnet {
		divFactor = diversityRepeatFactor // a repeat from an already-counted subnet
	}
```
then `contrib := obs.Trust * weightFor(obs.Reason) * (1 - rec.Score/100) * divFactor`,
and after the score/stranger bookkeeping:
```go
	if firstFromSubnet {
		rec.SubnetsSeen = append(rec.SubnetsSeen, obs.Subnet)
	}
```

`diversityRepeatFactor` is threaded in the same way `strangerCap`/`halfLife`
already are — as a parameter to `Accumulate` (and stored on the `Engine`),
so `Accumulate` stays pure.

**Backward compatibility (critical):** an empty `obs.Subnet` — a solo node
with no `federation_subnet`, or any pre-E1 event — leaves `divFactor == 1.0`
and does not touch `SubnetsSeen`, so scoring is **byte-for-byte as today**.
Diversity only differentiates once observations carry distinct non-empty
subnets. The stranger cap still applies on top (a stranger's contribution is
diversity-weighted *and* capped).

## 5. Native wiring (`internal/node`)

`processLocal` and `ProcessRemote` set `Observation.Subnet = e.SubnetID` —
the **originator's home subnet** stamped since E1, NOT the arrival subnet
(`re.Subnet`). Rationale: a bridge relaying a report must not be able to
launder a same-origin report into a fresh diversity vote by re-emitting it
into another subnet; diversity must reflect where the evidence *originated*.
A single peer's repeated reports and same-subnet floods therefore saturate
after the first vote.

## 6. Federated path (`internal/repquery`)

- `AggregateFromRecord` adds `DiversityBuckets["subnets"] = len(r.SubnetsSeen)`.
  Counts only — subnet ids never leave the node (§7.5 privacy, consistent
  with the existing groups/reporters buckets).
- `RecordFromEvidence` uses the `subnets` count to cap how much the `groups`
  folds benefit from diversity. Today it folds `groups` synthetic anchored
  votes at full weight; now the number of distinct subnets bounds how many
  of those are *full-weight* — the rest use `diversityRepeatFactor`:
  ```
  subnets := ev.DiversityBuckets["subnets"]
  fullVotes := min(groups, subnets)   // if subnets == 0, treat as 1 (a known IP came from ≥1 subnet)
  // fold fullVotes at full weight, (groups - fullVotes) at divFactor weight
  ```
  So an aggregator claiming 500 groups but 1 subnet recomputes like ~one
  diverse vote, not 500. This is both the §4.2 semantics for the federated
  path and a direct tightening of the E2 inflated-bucket vector. The
  Groups-empty invariant is preserved — the return stays a fresh literal
  carrying only Score/Reasons/FirstSeen/LastSeen.
- The `groups` fold-count cap (`maxEvidenceFolds`) and the Task-4 hardening
  (elapsed floor, weight clamp incl. NaN, score reclamp) remain.

## 7. Config

`Trust.DiversityRepeatFactor float64` (yaml `diversity_repeat_factor`).
Default `0.15`. `1.0` disables diversity weighting (a repeat counts the same
as a first — pure volume). Range clamp `[0,1]` on load. Locally overridable
(Leitprinzip 7). `docs/config.md`: "how much a repeat report from a subnet
that already reported this IP is worth, relative to the first report from a
new subnet; lower = stronger diversity weighting."

## 8. Security / invariants

- **Block gate untouched:** diversity weights the score only; a block still
  needs anchored-Person corroboration. Strangers/subnets cannot force a
  block (Leitprinzip 8, P0-1 backstop intact).
- **Bridge-launder resistant:** diversity keys on the originator's
  `SubnetID`, not the arrival subnet, so relaying cannot mint diversity.
- **Inflation-resistant:** the federated `subnets` count caps the diversity
  benefit of a large `groups` claim (tightens the E2 vector).
- **Read-only federated path** unchanged; **solo/single-subnet unchanged**
  (empty subnet ⇒ today's math).
- No new external data, no reporter geolocation, no hashing (§9 clean).
- Trust asymmetry (rise-slow/fall-fast) untouched — diversity scales the
  rise, decay is unchanged.

## 9. Testing

- **`Accumulate` diversity unit:** ten reports from one subnet ≈ first
  full + nine damped (score well below ten full votes); ten reports from ten
  distinct subnets = ten full votes (strictly higher); empty-subnet
  observation reproduces today's contribution exactly (equivalence); the
  stranger cap still bounds a diversity-weighted stranger.
- **Equivalence:** existing reputation + adversarial suites pass UNCHANGED
  (empty subnet path).
- **Node wiring:** `Observation.Subnet` populated from `e.SubnetID`; a
  bridge-relayed event's diversity keys on origin, not arrival (a re-emitted
  copy from another subnet does not add a fresh subnet vote for the same
  originator).
- **`AggregateFromRecord`:** `subnets` bucket = `len(SubnetsSeen)`, names not
  present anywhere on the aggregate.
- **`RecordFromEvidence`:** groups=500/subnets=1 recomputes far below
  groups=500/subnets=500; groups=3/subnets=3 unchanged from full folds;
  Groups-empty invariant still asserted.
- **Adversarial:** a single subnet flooding many reports for one IP saturates
  near a one-subnet score and never approaches a multi-subnet signal; the
  inflated-bucket test extended for the subnet cap.
- **Full gate:** build, vet, gofmt, unit, `-race` on repquery/reputation,
  adversarial, integration.

## 10. Docs

- `docs/config.md`: the `diversity_repeat_factor` knob.
- `docs/spec.md` §12a: §4.2 diversity-weighted corroboration → DONE
  (subnet-based; ASN/geo dimensions PLANNED).
- `docs/roadmap.md`: Step 3 ✅, A2 ✅.
- `docs/architecture.md`: one line — corroboration is subnet-diversity
  weighted (breadth over volume).

## 11. Acceptance

For a federated deployment, an IP reported many times from a single subnet
scores far lower than the same volume spread across many subnets; a solo /
single-subnet node scores byte-for-byte as before; the block gate still
requires anchored-Person corroboration; a federated aggregate with many
groups but one subnet recomputes as roughly one diverse vote; all suites
including the new adversarial single-subnet-flood scenario pass.
