# Materialise-on-Verdict (Roadmap Step 4)

**Status:** Design approved 2026-07-13
**Source:** [docs/roadmap.md](../../roadmap.md) Step 4 — item A5; the "push half"
deferred from E3 (E3 design §8). Spec §11.3 (O(1) enforcement), §11.4 (on-demand
query → enforce), §4.2 (diversity as Sybil resistance), Leitprinzip 8 (remote
input advisory).
**Prerequisite:** E3 (federated query), E2 (`EvidenceAggregate` + scale-free
recompute), D (subnet-diversity weighting) — all merged.
**Unblocks:** completes E3's "pull discovers, push enforces" synthesis.

---

## 1. Problem

E3 built the federated *read* path (a lookup for an IP that contacted you
returns a recomputed reputation), but it is advisory only — it never reaches
the firewall. E3 §8 deferred the "push half" until evidence was scale-free
(E2) and diversity-weighted (D). Step 4 delivers it: on a block-worthy
*federated* verdict for an IP that actually contacted you, push an O(1) block
into the enforce sink so subsequent packets drop in the kernel.

The obstacle: today a block is gated by the anchored-Person backstop
(`len(rec.Groups) == 0 → downgrade to watch`, node.go). E2's
`RecordFromEvidence` returns EMPTY `Groups` by design, so a federated verdict
run through today's logic is *always* downgraded. Step 4 needs a different,
equally-safe gate for the federated path.

## 2. Decisions made during brainstorming (user-selected)

1. **Federated gate = diversity floor + threshold.** Materialise iff the
   recomputed score ≥ a threshold AND the evidence shows independent breadth
   (`diversity_buckets["subnets"] ≥ floor`). Diversity (from D) is the
   Sybil-resistance substitute for anchored corroboration — forging broad
   multi-subnet breadth is exactly what D makes expensive. Bounded by D's
   subnet-cap, the trusted-aggregator model, and defederation.
2. **Short TTL, auto-expiring.** Materialised federated blocks carry a TTL
   and self-expire via the sink's own timeout; they re-materialise on the
   next lookup if the evidence persists. A forged/stale verdict or a
   reassigned IP (CGNAT/DHCP) heals within the TTL with no operator action —
   remote-sourced enforcement stays provisional (lists are aids; decay =
   deletion).

Two further choices adopted (recommended, not separately asked): a
**separate, higher `federation_block_threshold`** (not the local threshold),
and **opt-in, default OFF** (an operator must consciously enable
remote-sourced kernel drops).

## 3. Architecture — node owns the write; the resolver stays read-only

The Steps 1–3 read path (`repquery.Resolver`) keeps its read-only invariant:
it does not write the store or the firewall. Materialisation is a **node-owned,
gated side-effect** of a real southbound lookup:

- The DNSBL / per-IP score API serves a lookup for an IP that contacted a
  protected service ("IP that actually contacted you" — E3's trigger; no
  proactive global materialisation).
- When the answer is a *federated* hit (the local store missed and an
  aggregator answered), the node's **materialiser** — which lives in the
  node/enforce layer that already owns `sink.Block` + never-block/whitelist
  — evaluates the federated gate (§4) and, on pass, calls the sink with a TTL.

The materialiser needs the evidence's diversity signal, which the recomputed
`store.ScoreRecord` does not carry (it holds Score/Reasons/First/LastSeen
only). So the read path surfaces, alongside the record, the **merged
`EvidenceAggregate`** (or at minimum its `subnets` count and score) for the
materialise decision. The plan pins the exact seam; the constraint is that
the *write* stays in the node/enforce layer, never in `repquery`.

## 4. The federated gate

A federated verdict for IP X materialises a block iff ALL hold:
1. `federation_materialize` is enabled (default false).
2. X is not in the never-block set and not whitelisted (checked first, always
   win — identical precedence to the local path).
3. Recomputed score ≥ `federation_block_threshold` (default 80 — higher than
   the local `block_threshold`).
4. Evidence diversity `subnets ≥ federation_block_min_subnets` (default 3),
   read from the merged aggregate's `diversity_buckets["subnets"]`.

On pass → `sink.BlockFor(X, federation_block_ttl)`. On any fail → no write
(the answer remains advisory via DNSBL/API, exactly as Steps 1–3).

The local anchored-Person backstop is UNTOUCHED for local blocks; this is a
parallel, federated-only gate. Because D caps a low-diversity aggregate's
score (a single subnet can't reach a high recomputed score), conditions 3 and
4 reinforce each other — but both are checked explicitly, not inferred.

## 5. Enforce interface — timed blocks (`internal/enforce`, security-critical)

`Sink` gains `BlockFor(ip string, ttl time.Duration) error` (permanent
`Block(ip)` is unchanged — the local path keeps using it, byte-for-byte):
- **ipset:** the set is created with `timeout 0` (enables per-entry timeouts;
  a set without the timeout feature *rejects* `add … timeout`). `timeout 0`
  is backward-compatible — entries added via `Block` (no explicit timeout)
  never expire. `BlockFor` issues `ipset add <set> <ip> timeout <sec> -exist`.
- **nftables:** the deny set is declared with a `timeout` flag; `BlockFor`
  adds an element with the timeout.
- **CrowdSec:** `BlockFor` submits a decision with `duration = ttl` (the sink
  already models decision durations).

This is the invariant-7 surface: conservative defaults, extra review, and
`Block`'s existing behaviour must not change. The `timeout 0` change to
set-creation is the only edit to the local-block path and must be proven a
no-op for permanent entries.

## 6. Config (`internal/config`, all locally overridable — Leitprinzip 7)

- `federation_materialize` (bool, default **false**).
- `federation_block_threshold` (float64, default **80**).
- `federation_block_min_subnets` (int, default **3**).
- `federation_block_ttl` (duration, default **1h**), via an
  `EffectiveFederationBlockTTL()` accessor defaulting when unset.

Documented in `docs/config.md`: what materialisation is, that it is off by
default and remote-sourced, that blocks are provisional (TTL) and gated by
diversity + a high threshold, and that never-block/whitelist always win.

## 7. Security / invariants

- **Remote input still cannot force a *persistent* block.** Federated blocks
  are TTL-bounded and gated (diversity + high threshold); only local anchored
  evidence produces a persistent block. Leitprinzip 8 holds in spirit: remote
  is advisory + provisional, never authoritative.
- **never-block / whitelist precedence** is checked before any `BlockFor`,
  same as the local path (spec §10, install-detected local truth).
- **Enforcement O(1)** — `ipset`/`nftables` set add; no per-IP rule (spec
  §11.3 / problem Q).
- **`internal/enforce` + set-creation are security-critical** (CLAUDE.md
  invariant 7): `Block` unchanged; `BlockFor` + `timeout 0` reviewed
  conservatively; explicit operator opt-in.
- **Bounded by D:** a forged high-`groups`/one-subnet aggregate cannot
  materialise — D caps its recomputed score AND its `subnets` count is below
  the floor. Containment for a lying aggregator = defederation.
- **Self-healing:** TTL expiry clears stale/forged/reassigned blocks without
  operator action.
- Read path stays read-only; the write lives only in node/enforce.

## 8. Scope

**In:** `Sink.BlockFor` + the three backend impls + `timeout 0` set-creation;
the node materialiser + the federated gate; surfacing the merged aggregate's
diversity/score to the decision; config (4 keys); docs; adversarial scenario.
**Out:** changing the local block path or the anchored backstop; proactive /
non-contact materialisation; a distributed block set; signing `SubnetID`
(roadmap B7); disputes-driven unblock (roadmap Step 5); any change to the
gossip/ingest scoring path.

## 9. Testing

- **Gate unit:** materialise iff enabled ∧ score ≥ threshold ∧ subnets ≥
  floor ∧ ¬never-block ∧ ¬whitelist; each condition alone blocks
  materialisation; disabled ⇒ no-op.
- **`BlockFor` per backend:** ipset issues `add … timeout <sec>` (assert via a
  fake `run`); nftables timeout element; CrowdSec decision duration. `Block`
  path unchanged (regression).
- **Set-creation:** ipset `create … timeout 0` present; a permanent `Block`
  entry has no expiry (no-op proof).
- **Integration (two nodes):** aggregator B holds a diverse, block-worthy IP
  X; querier A (materialise enabled) looks X up → `BlockFor(X, ttl)` called;
  a single-subnet or below-threshold verdict → NOT materialised; a
  whitelisted/never-block X → never materialised even when block-worthy.
- **Adversarial:** a forged aggregate (huge `groups`, `subnets: 1`) cannot
  materialise (score capped by D below `federation_block_threshold` and/or
  subnets below floor); an aggregate for a never-block IP is refused.
- **Backward-compat:** `federation_materialize` off (default) ⇒ behaviour is
  byte-for-byte Steps 1–3; existing enforce/adversarial/integration suites
  pass unchanged.
- **Full gate:** build, vet, gofmt, unit, `-race`, `-tags adversarial`,
  `-tags integration`.

## 10. Docs

- `docs/config.md`: the four `federation_*` materialise keys.
- `docs/spec.md` §12a: §11.4 on-demand query → DONE (read + push, E3+Step 4);
  §4.4/E3 §8 materialise-on-verdict → DONE (Step 4).
- `docs/roadmap.md`: Step 4 ✅, A5 ✅.
- `docs/architecture.md`: the query read path can now materialise a
  provisional, diversity-gated, TTL-bounded block — completing "pull
  discovers, push enforces".
- `docs/threat-model.md`: remote-sourced enforcement is opt-in, provisional
  (TTL), diversity-gated, never-block-respecting; defederation is containment.

## 11. Acceptance

With `federation_materialize` enabled, a lookup for an IP that contacted a
protected service, answered by trusted aggregators with a high-score,
multi-subnet-diverse verdict, pushes a TTL-bounded O(1) block that
self-expires; a low-score, low-diversity, whitelisted, or never-block IP is
never materialised; the local block path and anchored backstop are unchanged;
with the feature off (default) behaviour is byte-for-byte as before; a forged
low-diversity aggregate cannot materialise; all suites including the new
adversarial scenario pass.
