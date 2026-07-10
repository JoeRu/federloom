# FederLoom — Critique & Suggestions

**Reviewer role:** critical architect
**Scope reviewed:** `docs/spec.md`, `docs/architecture.md`, and the Go
implementation under `internal/`, `pkg/`, `cmd/`, plus the shipped `deploy/`
configs and rules.
**Date:** 2026-07-07
**Resolution status (2026-07-10):** all P0s, all P2/P3, P1-4 and P1-5 are
resolved; P1-1 partially (pull read path shipped as E3). Remaining items and
their sequence live in [roadmap.md](roadmap.md) — this document is preserved
as the original findings record.
**Method:** read the two design docs first, then traced the real event path
(`ingest → reputation → rules → enforce → transport`) against what the spec
claims. Findings are grouped for two audiences: a candid limitations summary
(for adopters, in the spirit of `docs/prior-art.md`), then a prioritised
internal backlog with file references.

---

## Part 1 — Honest limitations (for adopters)

FederLoom's design document is ambitious and unusually well-reasoned. The
implementation is a genuinely working federated blocklist: it signs events,
verifies peers, resolves trust through anchored Person identities, decays
scores, and enforces via `ipset`/`nftables` O(1) sets. The seven invariants in
`CLAUDE.md` are largely respected in code.

But several **headline design properties are not yet implemented**, and a
reader of `spec.md` / `architecture.md` would reasonably assume they are. If
you are evaluating FederLoom, know the following before you rely on it:

1. **It does not scale by "query on-demand" yet — it gossips every event to
   everyone.** The architecture sells a DNSBL/DHT pull model with lightweight
   *evidence aggregates*. The running system push-replicates every raw
   `proto.Event` to every peer over gossipsub. This works for a handful of
   nodes and breaks exactly where the spec says a naïve design would. The
   pull model remains the target, not the current behaviour.

2. **Corroboration is not diversity-weighted.** The spec's central
   anti-poisoning claim — "N *independent* ASNs/countries, not N nodes" — is
   not in the code. There is no ASN, geography, or subnet-diversity dimension
   anywhere. Corroboration is a count of distinct anchored Person groups plus
   one shared "stranger" bucket.

3. **A single untrusted peer can make you block an arbitrary IP.** Several
   shipped rules block at `min_corroboration: 1`, and a lone stranger event
   satisfies that. The remote burst counter is likewise fed by unauthenticated
   peers. This is a live griefing/DoS injection vector on any federated node
   (see P0-1 below).

4. **IPv6 `/64` prefix normalisation does not exist**, though the spec marks
   the corresponding risk (Problem V) as "solved". An IPv6 attacker rotating
   within their `/64` currently defeats reputation entirely.

5. **Applicability weighting, dispute/anti-trust votes, and cross-subnet
   evidence import are unimplemented.** These are core to §4.4, §4.5, and
   §5.2. Fields for them exist in the wire contract (`Disputes`, `ScoreEntry`)
   but are never populated or exchanged.

None of these make the tool useless — as a trust-anchored honeypot feed among
a small, mutually-vouched federation it does real work. They do mean the
**decentralised-scaling and structural-anti-poisoning story is aspirational**,
and the docs should say so plainly until the code catches up.

---

## Part 2 — Prioritised backlog

Severity: **P0** = security/correctness, fix first · **P1** = design promise
unmet · **P2** = spec/impl drift · **P3** = docs/usage polish.

### P0 — Security & correctness

#### P0-1 · Remote peers can inject blocks (griefing / DoS)
**Where:** `internal/node/node.go:381-397` (ProcessRemote → rules → sink.Block),
`internal/reputation/engine.go:86-93`, `deploy/examples/rules.yaml`,
`deploy/honeypot/rules.yaml`.

The remote path scores an incoming event and immediately runs the rule engine,
which can return `ActionBlock`. Shipped rules like `honeypot-shell-exec` and
`honeypot-auth-success` fire at `min_corroboration: 1`. In the engine, a single
un-anchored ("stranger") report sets `StrangerSeen = true`, which bumps
`Corroboration` to 1 (`engine.go:91-93`). So **one message from any peer on the
topic** — trusted or not — with `reason: ssh-post-auth-command` causes the
receiving node to `ipset add` the attacker-chosen IP.

Because the default never-block set (see P0-3) does not include public
resolvers or provider ranges, a hostile peer can push a block for, e.g.,
`8.8.8.8`, a mail relay, or a competitor's address.

This arguably violates spec Leitprinzip 8 ("kein importiertes Signal … darf
bei dir einen Block … erzwingen"): today an imported signal *can* force a block.

**Suggestions (documented, not applied this pass):**
- Gate block-capable rules on `anchored_only: true` by default (the field
  already exists at `rule.go:51` but no shipped rule uses it).
- Stop counting the stranger bucket toward `Corroboration`, or require
  `min_corroboration ≥ 2` with at least one anchored group for any `block`
  action. (Engine-semantics change → needs a new adversarial scenario.)
- Add a "remote events may `watch` but never `block` unless anchored"
  guardrail in `ProcessRemote`.

#### P0-2 · Remote-fed burst counter is Sybil-trivial
**Where:** `internal/node/node.go:385` (`n.burst.Record` on remote events),
`internal/rules/rule.go:124-135`, rule `ssh-brute-burst` (15 events / 10 min).

`BurstStore` counts events per `(IP, reason)` with no per-reporter accounting,
and remote events feed it. A single peer can emit 15 `ssh-auth-bruteforce`
events naming a victim IP and trip `ssh-brute-burst → block`. Combined with
P0-1 this is a second independent injection path.

**Suggestion:** account bursts per distinct verified reporter, or only admit
anchored reporters into the burst window for block-triggering rules.

#### P0-3 · Shipped never-block default is narrower than spec §10
**Where:** `internal/enforce/neverblock.go:5-16` vs `docs/spec.md` §10.

The default set covers RFC1918/loopback/CGNAT/link-local/multicast/ULA only.
Spec §10 explicitly recommends also protecting public resolvers (`8.8.8.8`,
`1.1.1.1`), large mail-provider ranges (Google, Microsoft), and CDN/infra
ranges (Cloudflare). None of those ship. This is what makes P0-1's `8.8.8.8`
example land.

**Suggestion:** add a curated, operator-removable public-infrastructure
never-block list as a project default (it is, per §5.1/§10, a special case of a
project trust anchor). Keep it tunable but ship it populated.

#### P0-4 · Adversarial CI gate misses the enforcement path
**Where:** `test/adversarial/` (`poisoning_test.go`, `sybil_ingest_test.go`,
`vouch_test.go`).

The suite exercises reputation *score* caps and vouch resolution, but nothing
drives `rules.Evaluate → ActionBlock` from a remote stranger. The two most
dangerous behaviours (P0-1, P0-2) are exactly the ones with no adversarial
coverage, yet `CLAUDE.md` calls this suite the security gate.

**Suggestion:** add scenarios asserting that an unanchored remote reporter can
never cause a `Block`, and that burst rules require anchored corroboration.

#### P0-5 · Public UDP DNSBL responder is an abuse surface
**Where:** `internal/dnsbl/server.go:53-70`, `deploy/honeypot/docker-compose.yml:40`
(`"5353:5353/udp"` published to the host).

The DNSBL answers UDP queries from anywhere it is reachable. An open,
internet-exposed UDP responder is a classic reflection/amplification and
enumeration vector (anyone can probe "is IP X on your list?"). On the honeypot
node it is bound to `0.0.0.0:5353`.

**Suggestion:** bind DNSBL to loopback/Tailscale by default like the metrics
ports already are, document response-size/rate limits, and treat public
exposure as an explicit opt-in.

### P1 — Design promises not yet implemented

#### P1-1 · "Query on-demand" scaling is push-replication in practice
**Where:** `internal/transport/gossip.go:61-104` (FloodPublish gossipsub),
`internal/node/node.go:292-298`; contrast `docs/architecture.md` §"Why query
instead of replicate" and `spec.md` §11.4.

Every local event is `Publish`ed to the whole topic; every node scores every
event. The `EvidenceAggregate` type (§7.5) does not exist in code, and
`proto.ScoreEntry` (§7.2) is defined but **never exchanged on the wire** — only
`Event` is. The embedded DNSBL server reads the *local* store; it does not
perform a DHT lookup, so it is not the "on-demand query" mechanism the spec
describes — it just exposes the already-replicated data.

**Suggestion (target model retained):** keep the pull model as the goal;
document the current push model as the MVP transport and write a migration note
(introduce `EvidenceAggregate`, move enforcement to on-contact lookup, retire
raw-event fan-out). Until then, mark architecture.md's query claim as
"planned".

#### P1-2 · Corroboration has no diversity weighting
**Where:** `internal/reputation/engine.go:86-93`; spec §4.2.

`Corroboration = len(Groups) [+1 stranger]`. There is no ASN/country/subnet
bucketing (`grep` for `asn`/`country`/`diversity` in `internal/` returns
nothing but a doc comment). The spec's "10 reports from one ASN ≈ 1 vote"
property — the thing that makes poisoning expensive — is absent. The federated
`diversity_buckets` field (§7.5) has no code.

**Suggestion:** even a coarse ASN lookup (offline table) feeding a
diversity-weighted corroboration count would materially deliver the §4.2 claim.
Track as its own spec/plan cycle.

#### P1-3 · Dispute / anti-trust votes unimplemented
**Where:** `pkg/proto/messages.go:43` (`Disputes` never written),
`cmd/federloomctl/whitelist.go:31-46` (`shared-vote` scope accepted but never
federated or counted); spec §4.4.

`shared-vote` whitelist entries are storable but go nowhere — they are not
broadcast, not counted as negative trust-weighted votes, and `Disputes` stays
zero. The §4.4 "whitelisting many admins ⇒ strong legit signal, and a peer that
reports broadly-whitelisted IPs loses trust" loop does not exist.

**Suggestion:** either implement the dispute vote path or mark §4.4 and the
`Disputes`/`shared-vote` surface as reserved/future in the spec and wire docs.

#### P1-4 · IPv6 `/64` normalisation missing (Problem V not actually solved)
**Where:** `internal/node/node.go:255,333` (`addr.Unmap()` only); spec §7.1 and
§12 Problem V ("gelöst via Präfix-Normalisierung").

No prefix masking is applied to IPv6 addresses on ingest or on the wire. A
`/128` is stored verbatim, so an attacker owning a `/64` gets 2^64 free
identities. The spec claims this is solved; it is not.

**Suggestion:** apply configurable prefix normalisation (default `/64`) in the
event-normalisation step of both `processLocal` and `ProcessRemote`, and add a
test. Downgrade Problem V to "open" in the spec until then.

#### P1-5 · Federation origin-tracing / hop-discount inert at runtime
**Where:** `internal/node/node.go:366-380` (the code's own comment:
"gossipsub forwards raw bytes without appending relay hops to OriginTrace, so
len(OriginTrace) is always 1 … the cross-node A→B→A feedback-loop guard above
is not yet active at runtime"); spec §5.2, architecture.md §Federation.

`architecture.md` states origin tracing prevents A↔B double-counting. In
practice `OriginTrace` never grows past the originator, so both the per-hop
`FederationDiscount` and the loop guard are effectively no-ops. The mechanism
is scaffolded but not wired into the forwarding path.

**Suggestion:** implement hop-appending re-broadcast (or an explicit relay
layer) before claiming K/L are mitigated; until then soften architecture.md.

#### P1-6 · Applicability weighting / System-Profile absent
**Where:** no code for §4.5 / §7.6 (`roles[]`, SBOM, `applicable_scenarios`).

The "effektives Gewicht = Korroboration × Source-Trust × Applicability" formula
runs without its third factor. Reasonable to defer, but the spec presents it as
part of the consume-time model.

**Suggestion:** label §4.5/§7.6 as post-MVP in the spec's status line.

### P2 — Spec ↔ implementation drift

- **P2-1 · Deprecated `port_class` still in the wire contract.**
  `pkg/proto/messages.go:17` carries `PortClass`, which §7.1 marks
  *deprecated* ("entfällt zugunsten von `scenario`") specifically to avoid
  leaking service details. Either remove it (wire-protocol change) or update
  §7.1 to say it is retained. Note also the spec's data model uses `scenario`
  as the join-key, while the code's field is `Reason` — the naming divergence
  should be reconciled or explicitly mapped in the wire docs.
- **P2-2 · `proto.ScoreEntry` is dead weight on the wire.** Defined per §7.2
  but never sent. Mark reserved or remove.
- **P2-3 · Spec status/language mismatch.** `spec.md` header still reads
  "Status: Entwurf / Brainstorming-Ergebnis" with an unresolved working title
  ("Arbeitstitel: offen"), and the whole spec is in German while the codebase,
  comments, and all other docs are English. The README presents a shipped
  product. Pick one maturity signal; consider an English translation or at
  least an English status/traceability header, since the spec is the
  authority the code comments cite.
- **P2-4 · §13 "Nächste Schritte" is stale.** Several listed steps are done
  (enforcement backend = ipset/nftables, install-script, onboarding docs,
  discovery). There is no traceability matrix from spec sections to
  implemented packages, so a reader cannot tell what is live. A short
  "implemented / partial / planned" table would fix most P1/P2 confusion at
  once.

### P3 — Docs & usage

- **P3-1 · README federation-join path is wrong.** `README.md:43-44` says
  "bootstrap.sh already copied federation.invite there" and instructs
  `docker compose cp /opt/federloom/federation.invite …`. No bootstrap script
  copies `federation.invite`, and the mailcow bootstrap rsyncs the repo to a
  configurable `$REMOTE_DIR`, not `/opt/federloom`. The instruction will fail
  as written. Fix the path (point at the synced repo dir, e.g.
  `./federation.invite` from the deploy directory) and drop the false claim.
- **P3-2 · `docs/architecture.md` overstates two mechanisms** (query-model
  P1-1, origin-tracing P1-5). Add a one-line "current vs. target" caveat to
  each so the condensed doc doesn't mislead more than the full spec.
- **P3-3 · API is unauthenticated by default.** `internal/api/server.go:85`
  ships open unless `FEDERLOOM_API_TOKEN` is set. Reasonable for a
  loopback-bound service, but the blocklist endpoint is sensitive; document
  the exposure and recommend the token whenever the API is bound off-loopback.

---

## What is genuinely solid (so the critique is fair)

- Event authenticity: domain-separated Ed25519 signatures, spoof guard against
  `ReporterID != verified publisher`, vouch-replay rejection
  (`node.go:305-363`, `identity/sign.go`). This part is careful and correct.
- Trust store: hot-reload with last-good fallback, weight clamping to `(0,1]`,
  mtime+size change detection to survive coarse filesystem timestamps
  (`trust/store.go`). Invariant 6 (anchors locally removable, bad file never
  silently drops trust) is respected.
- Enforcement is O(1) via `ipset`/`nftables` hash sets, IPv4+IPv6, idempotent
  rule install (`enforce/ipset.go`) — invariant 4 met.
- Never-block + local-only whitelist are checked on **both** local and remote
  paths before any block (`node.go:256-261,348-353`) — invariants 3 respected
  for the ranges that *are* in the default set (see P0-3 for the gap).
- Rule engine: safe validation (drops unknown actions, zero-window bursts),
  last-good ruleset on parse error, per-invocation burst cache — defensive and
  well-tested.
- Stranger score cap (`strangerCap`) genuinely bounds un-anchored score
  contribution per IP — the reputation-layer Sybil defence works, which is why
  the *rule-layer* injection (P0-1/P0-2) is the more urgent hole.

---

## Recommended sequencing

1. **P0-1 → P0-4** together: they are one story (untrusted input reaching
   `Block`) and want one fix + one adversarial scenario.
2. **P0-3, P0-5**: small, shippable hardening of defaults.
3. **P1-4 (IPv6 /64)**: contained, high-value, testable.
4. **P2-4 traceability table + P3 doc fixes**: cheap, removes most of the
   "does it actually do X?" ambiguity for adopters.
5. **P1-1 / P1-2 / P1-5**: the real research-grade work — the decentralised
   scaling and structural-anti-poisoning claims. Each merits its own
   brainstorm → spec → plan cycle.

---

## Open questions for the maintainer

- **P1-2 diversity data source:** offline ASN table (MaxMind/IPtoASN) bundled
  with releases, or an optional lookup service? Bundling keeps the
  "no mandatory cloud calls" invariant but adds a large data file and a refresh
  cadence.
- **P0-1 fix boundary:** is "remote events may `watch` but only anchored
  reporters may cause `block`" an acceptable hard rule, or do you want it
  operator-tunable (which reopens the injection risk for anyone who loosens
  it)?
- **P2-3 spec language:** keep the authoritative spec in German and add an
  English pointer, or translate? This affects how the code's "spec §X"
  citations are consumed by contributors.
