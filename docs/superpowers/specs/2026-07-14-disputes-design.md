# Disputes / Anti-Trust Votes (Roadmap Step 5)

**Status:** Design approved 2026-07-14
**Source:** [docs/roadmap.md](../../roadmap.md) Step 5 — item A3 (critique P1-3).
Spec §4.4 (anti-trust / dispute feedback), §7.4 (whitelist entry,
`shared-vote` scope), §4.2 (diversity weighting), Leitprinzip 1/8 (local
sovereignty; remote advisory).
**Prerequisite:** E1 (subnet_id/signing), E2 (`EvidenceAggregate`), D
(subnet-diversity), Step 4 (materialise-on-verdict) — all merged.
**Unblocks:** the network-level correction of false positives, especially
undoing a Step-4 materialised block on a wrongly-listed IP.

---

## 1. Problem

The system can raise an IP's reputation and (Step 4) push a block, but there
is no network-level way to say "this IP is wrongly listed." §4.4 defines that
mechanism as **"local whitelist = a negative, trust-weighted vote"**, and
`proto.WhitelistEntry` already reserves a `Scope` of `"shared-vote"` that
nothing federates yet. Step 5 activates it: an operator who whitelists an IP
as `shared-vote` federates a signed dispute; nodes apply it as a
diversity-weighted negative vote that can lower the score and undo a
materialised federated block. §4.4 explicitly warns the counter-attack —
"mass whitelisting by Sybils could protect real attackers" — so disputes must
carry the **same diversity/trust weighting as block votes**.

Note: the user's original framing referenced `proto.ScoreEntry.Disputes`, but
E2 retired `ScoreEntry` (reserved/unused, slated for C1 removal). The dispute
signal rides the live federated type, `EvidenceAggregate`, instead.

## 2. Decisions made during brainstorming (user-selected)

1. **A dispute IS a federated `shared-vote` whitelist entry** (not a new
   parallel concept). Reuses the whitelist store, the local-only/shared-vote
   split, and event signing. `local-only` entries never federate (privacy,
   batch-A P0-3).
2. **Effect = diversity-weighted negative vote + unblock threshold.**
   Disputes subtract from the recomputed score, weighted by distinct
   disputing subnets × trust; crossing a dispute-diversity threshold actively
   unblocks a materialised federated block and suppresses re-materialisation.

Two further choices adopted (recommended, not separately asked): the vote is
carried on the wire as an **`Event` with `Kind:"vote"`** (planning decision
2026-07-14 — the transport gossips only `Event`; this reuses all of it without
overloading the attack-taxonomy `Reason`; see §4); and **unblock targets
federated materialised blocks ONLY** — never a local anchored block, which
stays under the operator's sovereign control.

## 3. Scope

**In:** the `Event.Kind:"vote"` wire discriminator + domain-separated vote
signing + gossip; a disputing-subnet
diversity tracker on the record + a negative branch in `Accumulate`; the
`dispute_subnets` bucket in `EvidenceAggregate` + dispute handling in
`RecordFromEvidence`; unblock-on-dispute-threshold for federated blocks;
`federloomctl whitelist --shared-vote` emitting the vote; config; adversarial
scenario; docs.

**Out:** ground-truth calibration / trust-slashing (§4.1 — "nodes that
whitelist honeypot IPs lose trust"; a future hook); disputing / unblocking a
LOCAL anchored block (local sovereignty); signing `SubnetID`/`OriginTrace`
(roadmap B7 — disputes inherit the same limitation and containment,
defederation); any change to the report-scoring or Step-4 gate beyond
subtracting the dispute contribution.

---

## 4. Wire: a dispute is an `Event` with `Kind:"vote"` (`pkg/proto`, additive)

**Wire-carriage decision (planning, 2026-07-14):** the transport gossips only
`proto.Event` (`json.Marshal(proto.Event)` → topic). Rather than build a
parallel vote gossip channel for a standalone `WhitelistVote` struct, a dispute
travels as an `Event` with a new discriminator field `Kind`. This reuses the
entire transport, signing, dedup, anti-spoof guard, gossip, and `ProcessRemote`
routing — the node branches on `e.Kind`. It does NOT overload `Reason` (the
attack taxonomy — the concern that ruled out that approach). The
"`WhitelistVote`" of the original design is the logical view; the wire type is
`Event`+`Kind`.

```go
// Event.Kind discriminates a report from a dispute vote. "" (default) = a
// report/attack observation (backward-compatible); "vote" = a federated
// shared-vote dispute (spec §4.4): a signed "this IP is legitimate" negative,
// diversity-weighted reputation vote. A vote reuses Event's IP / ReporterID /
// SubnetID / Timestamp / Signature; Reason is empty for a vote.
Kind string `json:"kind,omitempty"`
```

**Signing (domain separation):** a vote is signed with a distinct domain
string so a report and a vote for the same IP are not interchangeable and
existing report signatures stay byte-for-byte identical. `SignEvent`/
`VerifyEventSig` select the message by `Kind`: reports keep
`"federloom-event-v1"|IP|Reason|Timestamp|ReporterID` unchanged; a vote signs
`"federloom-vote-v1"|IP|Timestamp|ReporterID`. As with events, `SubnetID` is
not covered (roadmap B7 — a relay could only *reduce* dispute diversity, the
safe direction: a bad IP stays blocked). The public key is embedded in
`ReporterID` for trust resolution.

Gossiped on the existing events topic via the unchanged `transport.Publish`
(leaf/bridge behavior identical to events); received votes are deduped by the
existing dedup cache (its key already includes `Reason` — a vote has
`Reason:""` and `Kind:"vote"`, distinct from any report, so no collision).

## 5. Recording & propagation

**Disputing node** (`internal/node`, `internal/store`): `whitelist add
--shared-vote <ip>` records a `WhitelistEntry{Scope:"shared-vote"}` locally
(existing store; still gates local blocks via `Contains`) AND publishes a
signed vote `Event` (`Kind:"vote"`). `local-only` entries are unchanged and never emitted.
A node also records its OWN vote into its store so its local record reflects
the dispute (and it counts toward the aggregate it may serve).

**Receiving node** (`ProcessRemote`-parallel path): verify the signature and
publisher (same anti-spoof guard as events); resolve the reporter's trust
(anchored weight / stranger weight via `trust.Store`); apply the dispute to
the IP's record (§6). A blocked/defederated peer's votes are dropped
(`trust.IsBlocked`), same as events.

## 6. Score effect — diversity-weighted negative vote

`store.ScoreRecord` gains `DisputeSubnetsSeen []string` (distinct subnets that
have disputed this IP — SEPARATE from `SubnetsSeen`; report-diversity and
dispute-diversity must never be conflated) and `DisputeContrib float64`
(cumulative points subtracted, for auditing/bounding).

`reputation.Accumulate` gains a dispute path (a new `Observation` kind, or a
sibling `ApplyDispute`): a dispute from a NEW disputing subnet subtracts a
full `disputeWeight × trust × (score/100)` contribution; a repeat from an
already-counted disputing subnet is damped by the existing
`diversityRepeatFactor` (reuse D). The score floors at 0. Anchored disputers
count per distinct group; strangers share one capped bucket (symmetric with
the stranger cap on reports, so a stranger dispute-flood is bounded). The
block gate / anchored-corroboration backstop for *reports* is untouched —
disputes only ever *reduce* the score.

**Asymmetry (Leitprinzip):** trust rises slowly / falls fast — a dispute that
corrects a false positive is meant to be responsive, but Sybil-bounded, so a
dispute's downward pull is gated by *diversity*, not raw count.

## 7. Unblock threshold (undo a Step-4 block)

When the count of distinct `DisputeSubnetsSeen` for an IP that currently has a
**materialised federated block** reaches `dispute_unblock_min_subnets`
(default 3, symmetric to `federation_block_min_subnets`), the node:
1. calls `sink.Unblock(ip)`, and
2. marks the IP disputed so `materialiseFederated` (Step 4 gate) refuses to
   re-materialise while the dispute-diversity threshold holds.

**Local anchored blocks are never touched** by a remote dispute (Leitprinzip
1/8): a federated dispute lowers the advisory score, but a block the operator
raised from their own anchored evidence remains theirs to clear (their own
`shared-vote`/`local-only` whitelist already removes it locally). The Step-4
materialiser only ever created federated blocks, so the unblock symmetry is
exact — dispute undoes what a federated verdict did, nothing local.

Because `materialiseFederated` gates on the recomputed score, and the dispute
subtraction lowers it, the two mechanisms reinforce: even without the active
Unblock, a disputed IP's TTL-bounded block would fail to re-materialise on the
next lookup and self-clear. The active Unblock makes it prompt.

## 8. Federated loop via `EvidenceAggregate`

- `AggregateFromRecord` adds `DiversityBuckets["dispute_subnets"] =
  len(r.DisputeSubnetsSeen)` (counts only — no subnet names, §7.5 privacy).
- `RecordFromEvidence` subtracts a dispute contribution scaled by
  `dispute_subnets` (capped like the groups fold), so a federated verdict for
  a disputed IP recomputes lower. This is how a node that queries (rather than
  gossips with) the disputing subnets still sees the dispute — closing the
  loop with E2/D/Step-4. The Groups-empty invariant is preserved (the returned
  record still carries no corroboration fields).

## 9. Security / invariants

- **Sybil-resistant (§4.4):** disputes are diversity+trust weighted; a single
  subnet or a stranger flood cannot lower a score materially or trip the
  unblock threshold. Strangers are additionally cap-bounded.
- **Local sovereignty (Leitprinzip 1/8):** remote disputes never unblock a
  local anchored block, never mutate a local-only whitelist, and every
  parameter (weights, thresholds) is locally overridable.
- **Read/enforce safety:** the only new enforcement effect is `sink.Unblock`
  (removing a block is the safe direction); disputes never create a block.
- **Privacy/GDPR:** `local-only` never federates; disputes accelerate a
  legitimate IP toward score-0 deletion (decay-as-deletion aligned); only
  counts on the wire (no subnet names, no whitelist contents beyond the IP).
- **Containment:** a misbehaving disputer is defederated (`blocked_peers`),
  same as a misbehaving reporter; unsigned `SubnetID` (B7) can only *reduce*
  dispute diversity (safe direction — keeps a bad IP blocked), never
  fabricate it.

## 10. Config (`internal/config`, all locally overridable)

- `dispute_weight` (float64, default e.g. `10`) — per-vote downward strength,
  analogous to a report reason weight.
- `dispute_unblock_min_subnets` (int, default 3) — distinct disputing subnets
  to actively unblock a materialised federated block.

## 11. Testing

- **`Accumulate` dispute unit:** N disputes from 1 subnet ≈ one damped vote;
  N from N subnets pull the score down proportionally; score floors at 0;
  stranger dispute-flood bounded by the cap; report-diversity vs
  dispute-diversity kept separate.
- **Vote signing/verify:** `SignEvent`/`VerifyEventSig` on a `Kind:"vote"`
  event round-trip; report signatures stay byte-for-byte unchanged
  (equivalence); a forged / replayed / blocked-peer vote is dropped (mirror
  the event tests).
- **Unblock threshold:** a materialised federated block is Unblocked once
  distinct disputing subnets reach the floor; below the floor it stays;
  re-materialisation is suppressed while disputed. A **local** anchored block
  is NEVER unblocked by a remote dispute.
- **Federated loop:** `AggregateFromRecord` ships `dispute_subnets`;
  `RecordFromEvidence` recomputes a disputed IP lower; Groups-empty preserved.
- **Adversarial:** a Sybil dispute-flood (many votes, 1 subnet / all
  strangers) cannot clear a genuinely block-worthy IP; a diverse anchored
  dispute set can.
- **Backward-compat:** no shared-vote entries / no votes ⇒ behaviour
  byte-for-byte as today; existing suites pass unchanged.
- **Full gate:** build, vet, gofmt, unit, `-race`, adversarial, integration.

## 12. Docs

- `docs/config.md`: `dispute_weight`, `dispute_unblock_min_subnets`; how
  `whitelist --shared-vote` federates a dispute; local-only never shared.
- `docs/spec.md` §12a: §4.4 anti-trust/dispute → DONE (federated shared-vote
  votes, diversity-weighted, unblock threshold).
- `docs/roadmap.md`: Step 5 ✅, A3 ✅.
- `docs/architecture.md` + `docs/threat-model.md`: the negative-vote path,
  Sybil bounding, local-sovereignty boundary, unblock-federated-only.

## 13. Acceptance

An operator whitelisting an IP as `shared-vote` federates a signed dispute;
receiving nodes apply it as a diversity-weighted negative vote that lowers the
recomputed score; once distinct disputing subnets reach the floor, a
materialised federated block for that IP is unblocked and not
re-materialised, while a genuinely block-worthy IP survives a single-subnet /
stranger dispute-flood; a local anchored block is never unblocked by a remote
dispute; with no shared-vote entries, behaviour is byte-for-byte as today; all
suites including the new adversarial scenario pass.
