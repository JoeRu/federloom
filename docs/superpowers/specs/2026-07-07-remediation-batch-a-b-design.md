# Remediation Batch A+B — Security Hardening & Doc Truth-Up

**Status:** Design approved 2026-07-07
**Source:** `docs/critics-and-suggestions.md` (architect critique, 2026-07-07)
**Scope of this doc:** the full remediation roadmap for all critique points,
plus a **detailed, buildable design for the first shippable batch (A+B)**.
Sub-projects C, D, E are decomposed here but specified only at roadmap depth —
each gets its own brainstorm → spec → plan cycle later.

---

## 1. Remediation roadmap (all critique points)

The critique lists ~20 points (P0–P3). They differ enormously in size and risk,
so they are decomposed into five sub-projects. A+B ship together as one batch.

| Sub-project | Critique points | Nature | Sequence |
|---|---|---|---|
| **A · Security hardening + housekeeping** | P0-1, P0-2, P0-3, P0-4, P0-5, dep bump | Contained, urgent | **This batch** |
| **B · Doc/spec truth-up** | P2-1†, P2-2†, P2-3, P2-4, P3-1, P3-2, P3-3 | Doc-only, cheap | **This batch** |
| **C · IPv6 `/64` normalization** | P1-4 | Small feature | Next cycle |
| **D · Diversity-weighted corroboration** | P1-2 | Research | Own cycle |
| **E · Federated evidence & scaling** | P1-1, P1-5, P1-3, P1-6 | Research cluster | Own roadmap |

† P2-1 (`port_class` removal) and P2-2 (`ScoreEntry` removal) are wire-protocol
changes. In this batch they are only **documented** (deprecated-retained /
reserved). Actual removal defers to a future wire-protocol cycle so A+B stays
low-risk and shippable.

**Sequencing rationale**
- **A+B now:** security holes are live on deployed nodes; honest docs ship in
  the same PR.
- **C next:** IPv6 `/64` normalization is contained, testable, high-value.
- **D:** needs an ASN-data-source decision (bundled offline table vs optional
  lookup service — an explicit open question, see §5). Research cycle.
- **E:** the query/pull scaling model **remains the target** (decided). Within
  E, P1-5 origin-tracing comes first because it makes the existing
  `FederationDiscount` actually function; then `EvidenceAggregate` + on-demand
  pull transport; then dispute votes (P1-3) and applicability weighting (P1-6).
  E will decompose further into its own sub-specs.

Everything below §2 concerns **only batch A+B**.

---

## 2. Batch A+B — architecture & invariants

Batch A+B touches three planes but stays inside existing boundaries:

- **Control plane** — `internal/reputation/engine.go` (corroboration
  semantics), `internal/node/node.go` (burst gating). Security-critical: change
  is surgical, covered by new adversarial scenarios.
- **Data plane** — `internal/enforce/neverblock.go` (default set). Invariant 7:
  conservative defaults, no per-IP rules changed.
- **Docs** — `README.md`, `docs/architecture.md`, `docs/spec.md`,
  `docs/config.md`, `pkg/proto/messages.go` comments.

**Invariants preserved (CLAUDE.md):**
1. *Lists are aids* — every changed default stays locally overridable. The new
   never-block resolvers and the anchored-corroboration rule are defaults the
   operator can tune (rules.yaml, config).
3. *Local-only whitelist never federated* — unchanged.
4. *Enforcement O(1)* — unchanged (never-block is a prefix set, not per-IP
   rules).
5. *Trust rises slowly, falls fast* — the engine change only removes an
   incorrect corroboration inflation; decay/asymmetry untouched.
7. *`enforce/` + `scripts/install/` security-critical* — never-block change is
   additive (more protection), reviewed with new tests.

**Guiding principle for A:** untrusted remote input may raise an IP's *score*
(already capped at `strangerCap = 15`, below the `min_score:75` fallback) and
may trigger a `watch`, but it must never structurally cause a **block**
(spec Leitprinzip 8). Blocks require anchored corroboration or local evidence.

---

## 3. Sub-project A — Security hardening (detailed)

### A1 · Engine corroboration gate
**File:** `internal/reputation/engine.go` (`Record`, lines ~86-93).

**Current:**
```go
rec.Corroboration = len(rec.Groups)
if rec.StrangerSeen {
    rec.Corroboration++
}
```
A single un-anchored reporter sets `StrangerSeen = true`, so `Corroboration`
becomes 1 and satisfies `min_corroboration: 1` block rules.

**Change:** corroboration counts distinct **anchored** Person groups only:
```go
rec.Corroboration = len(rec.Groups)
```
Remove the stranger bump. Keep `StrangerSeen` and `StrangerContrib` (still used
by the score cap and by the `AnchoredOnly` rule check).

**Consequences (must hold, asserted by tests):**
- A lone remote stranger → `Corroboration == 0` → cannot satisfy
  `min_corroboration: 1`.
- Local honeypot events call `Record(..., group=selfID, anchored=true)` → count
  as one anchored group → local blocks still fire.
- An anchored remote reporter (vouched Person the node anchors) → counts as its
  group → can still corroborate/block. Legit federation path intact.
- Strangers still add score up to `strangerCap` (15), which stays below the
  `min_score:75` fallback, so the score path remains non-injectable.

### A2 · Burst gate
**File:** `internal/node/node.go` (`processLocal` ~line 277, `ProcessRemote`
~line 385).

**Current:** both paths call `n.burst.Record(e.IP, e.Reason, time.Now())`
unconditionally, so 15 stranger events trip `ssh-brute-burst → block`.

**Change:** feed the burst window only for anchored observations.
- `processLocal`: local events are self-originated (anchored) → keep recording.
- `ProcessRemote`: record into burst **only when `anchored == true`** (the
  value already returned by `n.trust.Resolve(e.ReporterID)`).

Strangers therefore never contribute to a `min_burst` block rule. They still
get score (capped) and can still trigger `watch` rules.

**Interface note for the implementer:** `anchored` is already in scope in
`ProcessRemote` after the `Resolve` call. No signature changes needed.

### A3 · Never-block default expansion
**File:** `internal/enforce/neverblock.go` (`defaultNeverBlock`).

**Change:** add public-resolver `/32`s to the always-on default set:
`8.8.8.8/32`, `8.8.4.4/32`, `1.1.1.1/32`, `1.0.0.1/32`, `9.9.9.9/32`,
`149.112.112.112/32` (Quad9 secondary).

**Deliberately NOT hardcoded:** broad provider/CDN ranges (Google, Microsoft,
Cloudflare). Per spec caveat N, over-broad auto-whitelisting is a hazard. These
are instead **documented in `docs/config.md`** as recommended operator
additions via `enforce.extra_whitelist`, with the exact CIDR lists.

**Rationale:** closes the P0-1 "block `8.8.8.8`" example as defense-in-depth
while respecting invariant 1 (operator can still remove any entry by editing
config; the hardcoded resolvers are the safe default, and a future cycle may
make the public-infra layer config-toggleable if an operator objects).

### A4 · Adversarial coverage
**File:** `test/adversarial/injection_test.go` (new).

Scenarios (drive `Node.ProcessRemote` / `processLocal` directly, as the
existing suite does):
1. **Stranger corroboration injection blocked:** an un-anchored remote event
   with `reason: ssh-post-auth-command` (matches `honeypot-shell-exec`
   `min_corroboration:1`) → assert the sink received **no** block.
2. **Stranger burst injection blocked:** 15 un-anchored `ssh-auth-bruteforce`
   remote events for one IP → assert **no** block (`ssh-brute-burst` not
   tripped).
3. **Anchored path regression:** an anchored remote reporter emitting the same
   `ssh-post-auth-command` event → assert the IP **is** blocked (gate does not
   break legit corroboration).
4. **Local evidence regression:** a local honeypot `ssh-auth-success` event →
   assert the IP **is** blocked.

Use a mock `enforce.Sink` (pattern already in `test/adversarial/`) to observe
Block calls. These become part of `make adversarial`, the CI gate.

### A5 · Dependency bump (Dependabot alert #2)
`golang.org/x/net v0.53.0 → v0.55.0` (indirect; HTML-parser DoS, unused by the
main module but clears the alert):
```bash
go get golang.org/x/net@v0.55.0
go mod tidy
make build test
```
Commit `go.mod`/`go.sum` changes.

### A-others · DNSBL binding (P0-5)
**File:** `deploy/honeypot/docker-compose.yml` (port publish) +
`docs/config.md` / `docs/dnsbl-integration.md`.

The DNSBL is an open UDP responder. **Change (config/deploy only, no Go code):**
- Default the honeypot compose to bind DNSBL to the Tailscale/loopback interface
  like the metrics ports already are (`100.71.239.1:5353:5353/udp` instead of
  `5353:5353/udp`), OR document that public exposure is an explicit opt-in.
- Add a `docs/` note: public DNSBL exposure is a reflection/enumeration surface;
  recommend loopback/VPN binding and rate-limiting if exposed.

No engine change; this is a deployment-default hardening.

---

## 4. Sub-project B — Doc/spec truth-up (detailed)

All doc-only; no runtime behaviour changes. `port_class`/`ScoreEntry` are
**documented**, not removed.

- **B1 · README join path (P3-1)** — `README.md` ~lines 43-44. The mailcow
  bootstrap rsyncs the whole repo (including `federation.invite`) to
  `$REMOTE_DIR`; there is no `/opt/federloom` copy step. Fix: reference the
  file at its real synced location (repo root under the deploy dir) and delete
  the false "bootstrap.sh already copied … there" claim. Verify the corrected
  command against `deploy/mailcow/bootstrap-mailcow.sh`.
- **B2 · architecture.md caveats (P3-2, supports P1-1/P1-5)** — add a one-line
  "current vs target" caveat to two paragraphs: the "query instead of
  replicate" section (today it push-replicates every event; pull is the target)
  and the federation origin-tracing claim (hop-appending not yet wired at
  runtime; the discount/loop-guard are currently inert — cite `node.go`
  comment).
- **B3 · spec traceability table (P2-3, P2-4)** — the status header is already
  updated by the maintainer. Add one new subsection (English) to `docs/spec.md`:
  an **implementation traceability table** mapping spec sections → package →
  status `DONE / PARTIAL / PLANNED`. This supersedes the stale §13 "Nächste
  Schritte" as the source of truth for what's live. Minimum rows:

  | Spec § | Area | Package | Status |
  |---|---|---|---|
  | §4.1 | Ground-truth anchors | `internal/trust`, honeypot ingest | DONE |
  | §4.2 | Diversity-weighted corroboration | — | PLANNED (D) |
  | §4.3 | Asymmetric decay | `internal/reputation` | DONE |
  | §4.4 | Dispute / anti-trust votes | — | PLANNED (E) |
  | §4.5 | Applicability weighting | — | PLANNED (E) |
  | §5.1 | Trust anchors | `internal/trust` | DONE |
  | §5.2 | Federation import / discount / origin-trace | `internal/node`, `internal/trust` | PARTIAL (discount present, origin-trace inert — E) |
  | §7.1 | Event model | `pkg/proto` | DONE (`port_class` deprecated-retained) |
  | §7.2 | ScoreEntry aggregate | `pkg/proto` | RESERVED (defined, not exchanged) |
  | §7.5 | EvidenceAggregate | — | PLANNED (E) |
  | §7.6 | System profile / SBOM | — | PLANNED (E) |
  | §7.1 (IPv6) | `/64` prefix normalization | — | PLANNED (C) |
  | §11.3 | O(1) enforcement (ipset/nftables) | `internal/enforce` | DONE |
  | §11.4 | On-demand query / pull | — | PLANNED (E; current = push) |
  | §14 | Federation discovery | `internal/discovery` | DONE |

  (The implementer fills any rows discovered while cross-checking packages.)
- **B4 · wire-contract comments (P2-1, P2-2)** — in `pkg/proto/messages.go`:
  mark `PortClass` as deprecated-retained (removal is a future wire cycle),
  mark `ScoreEntry` as reserved / not-yet-exchanged, and add a one-line note
  that the wire field `Reason` is the spec's `scenario` join-key.
- **B5 · API-auth + never-block docs (P3-3, supports A3)** — in
  `docs/config.md` (and/or `getting-started.md`): document that the REST API is
  unauthenticated unless `FEDERLOOM_API_TOKEN` is set, recommend the token
  whenever the API binds off-loopback, and list the recommended provider/CDN
  never-block CIDRs operators can add via `extra_whitelist`.

---

## 5. Out of scope for this batch / open questions

**Out of scope (roadmap sub-projects C/D/E):** IPv6 `/64` normalization; ASN
diversity weighting; `EvidenceAggregate` + pull transport; runtime origin-trace
hop-appending; dispute/anti-trust vote path; applicability weighting; actual
removal of `port_class` and `ScoreEntry` from the wire.

**Open questions (do not block A+B; resolve when their sub-project starts):**
- **D — diversity data source:** bundle an offline ASN table
  (MaxMind/IPtoASN) with releases (keeps the "no mandatory cloud calls"
  invariant, adds a large data file + refresh cadence) vs an optional lookup
  service. Decide at the start of sub-project D.
- **A3 follow-up:** if any operator objects to hardcoded public-resolver
  protection, a later cycle can make the public-infra layer config-toggleable.
  Not needed for the safe default now.

---

## 6. Testing & acceptance

- `make build` — compiles.
- `make test` — full unit suite green, including the modified engine/node.
- `make adversarial` — **new `injection_test.go` scenarios pass**; existing
  poisoning/sybil/vouch scenarios still pass (regression).
- `go vet` / `make fmt lint` — clean.
- Manual doc check: the traceability table rows match actual package presence;
  the corrected README join command matches `bootstrap-mailcow.sh`.

**Acceptance:** a remote un-anchored peer can no longer cause any receiving node
to block an IP (asserted by A4-1 and A4-2), while local honeypot evidence and
anchored-federation corroboration still block (A4-3, A4-4). Dependabot alert #2
cleared. Docs no longer overstate query-model / origin-tracing, the README join
path works, and the spec carries an honest traceability table.
