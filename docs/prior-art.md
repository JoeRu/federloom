# Prior Art: FederLoom vs. existing federation & threat-intel systems

> **Status: draft / brainstorming scaffold.** Purpose: position FederLoom honestly
> against established systems, separate what we *borrow* from what is *genuinely
> new*, and surface interop opportunities. Directly addresses the "don't reinvent
> trust — check against existing solutions" review feedback.
>
> Sections marked **[OPEN]** need a decision; **[VERIFY]** needs a citation/fact-check
> before this doc is published.

## TL;DR positioning

**FederLoom = STIX-like reputation content + MISP-like sharing-community trust —
but *earned and weighted* rather than manually configured, distributed over a
Matrix-like signed P2P mesh instead of a central hub.**

Almost every prior system uses **static, manually-configured, binary** trust
between **known** instances (MISP sync, TAXII collections, OCM trusted servers),
or **open federation with reactive moderation** (Matrix). FederLoom's contribution
is **dynamic, earned, diversity-weighted, decaying** reputation plus **structural
anti-poisoning**.

### Honesty boundary (read before claiming novelty)

FederLoom's trust *between nodes* is **not** especially novel — curated anchors +
invite + fingerprint is conceptually close to MISP sharing groups and OCM trusted
servers. The genuine novelty lives in four places:

1. **Reputation of the *data* (per IP)** — score + asymmetric decay +
   diversity-weighted corroboration. MISP correlates but does not dynamically
   score sources/indicators this way.
2. **Structural anti-poisoning** — ground-truth anchors + independence weighting.
   The others largely reduce to "trust your partners".
3. **P2P transport + on-demand query** — gossip/DHT + DNSBL-style lookup, vs.
   central hub / pairwise sync / full replication.
4. **Applicability weighting** — locally weighting a signal by whether it is even
   relevant to *my* system (profile/role + SBOM). No comparator does this.

**Strongest honest claim (Matrix-derived):** FederLoom builds the *verifiable-trust
and score-aggregation layer that Matrix's policy lists explicitly left as future
work*. Matrix's shipped mechanism (MSC2313) assumes pure **social trust** ("don't
use it if you don't trust the creator") and its numeric-reputation successor
(MSC3845) is still a **draft**, stuck on exactly the score-combination problem
FederLoom answers (diversity-weighting + decay + local threshold). So the claim is
not "we invented federated blocklists" (Matrix shipped that) but "we built the
trust/aggregation layer on top that the prior art deferred".

Claim these; do **not** oversell "earned source trust" — node trust is
deliberately as conservative as the incumbents.

## Comparison at a glance

| System | Primary domain | Topology | Trust establishment | Trust dynamics | Anti-abuse model | Data model |
| --- | --- | --- | --- | --- | --- | --- |
| **FederLoom** | IP reputation / blocklist | P2P gossip + DHT (libp2p) | curated anchors + invite/fingerprint | **earned, weighted, decaying** | **structural** (ground-truth + diversity corroboration) | custom (`pkg/proto`) |
| **MISP** | General CTI (IOCs) | Hub / pairwise instance sync | manual sync users + sharing groups | static (configured) | partner trust + TLP scoping | events + attributes, taxonomies/galaxies |
| **STIX/TAXII** | CTI data + transport | Client-server (TAXII collections, polling) | server auth + collection access | static; `confidence`+`valid_until` per object | TLP marking-definitions | STIX 2.x (JSON SDOs/SROs) |
| **Matrix** | Real-time messaging | Federated homeservers (signed event DAG) | server signing keys + cross-signing | **social trust** (MSC2313); numeric reputation still draft (MSC3845) | open federation + subscribable policy/ban lists (Draupnir) | room events (DAG, state res); `m.policy.rule.*` |
| **OCM / Nextcloud** | File sync & share | Pairwise server federation | **trusted servers** + invite flow | static/binary | admin-curated trust | OCM share payloads |

*[VERIFY] current OCM trust-flow details before publishing. (Matrix row verified
against MSC2313/MSC3845/Draupnir, Jun 2026.)*

---

## MISP (Malware Information Sharing Platform & Threat Sharing)

**What it is.** The de-facto open-source standard for sharing threat intelligence:
events containing attributes (IOCs — IPs, hashes, domains), enriched with
taxonomies, galaxies, and a correlation engine that finds overlaps across events.

**Trust & federation model.** Instance-to-instance **synchronization** via sync
users; sharing controlled by **distribution levels** (org-only → this community →
connected communities → all) and explicit **sharing groups**. Trust is
**organizational and manual** — admins choose who to sync with and at what level.
No automatic, earned reputation of sources.

**What FederLoom borrows.**
- The **TLP / distribution-level / sharing-group vocabulary** — a proven language
  for "who sees what". Could map onto FederLoom's federation modes (allowlist/
  blocklist, trust-discount). **[OPEN]** adopt TLP tags directly?
- The **correlation engine** is conceptually FederLoom's corroboration, centralised.

**What FederLoom does differently.**
- P2P gossip mesh vs. configured pairwise sync.
- Earned, decaying, diversity-weighted reputation vs. static manual trust.
- Structural anti-poisoning vs. "a compromised sync partner poisons you".
- Narrow IP scope / lean sidecar vs. heavyweight full-CTI platform.

**Interop opportunity.** **Decision (Q2):** MISP is an **ingest/input** adapter
(`ingest.Source`) — import MISP events as attack signals — added **post-MVP**.
Mirror of the STIX decision: MISP *in*, STIX/TAXII *out*. Positions FederLoom as
**complementary**, not competitive.

---

## STIX / TAXII

**What it is.** **STIX** = structured CTI data language (STIX 2.x, JSON: indicators,
attack-patterns, relationships, observed-data). **TAXII** = the transport protocol
to exchange it (HTTPS, collections + channels, client polls/pushes a TAXII server).

**Trust & data model.** TAXII is **client-server** (poll a server, collection-level
access control). STIX `indicator` objects already carry **`confidence`** and
**`valid_from`/`valid_until`**, and **TLP marking-definitions** for handling.

**What FederLoom borrows.**
- STIX `indicator.confidence` + `valid_until` are **conceptually identical** to
  FederLoom's score + decay — validates the design and gives a clean **export
  mapping target**. **Decision (Q1):** *not* an internal schema — STIX/TAXII is an
  **egress/client feature**: the FederLoom client reads the federation and
  **publishes events to downstream systems** (SIEM/TIP) as STIX over TAXII. Keeps
  the core lean; adds interop at the edge.
- STIX `attack-pattern` / relationships could carry the **attack-vector /
  target-service descriptor** for the applicability idea (see "System profile"
  below).

**What FederLoom does differently.**
- One-line contrast: **"STIX-like content over a P2P transport instead of TAXII."**
  Decentralised gossip/DHT vs. centralised polling.

**Interop opportunity.** STIX/TAXII **export** = credibility + integration with the
whole CTI tool landscape, without adopting the heavyweight schema internally.

---

## Matrix

**What it is.** Decentralised real-time messaging: federated homeservers replicating
an eventually-consistent, signed DAG of room events, with state resolution.

**Trust & crypto model.** Per-homeserver **ed25519 signing keys**, signed events,
**cross-signing** for device/user verification, key servers, key rotation. Open
federation by default, with server allow/deny lists.

**How Matrix actually does shared reputation (verified Jun 2026).**
- **MSC2313 — moderation policy rooms (merged into the spec, 2020).** Ban lists are
  room **state events** `m.policy.rule.user|room|server`, each with `entity` (glob
  supported), a `recommendation` (e.g. `m.ban`), and a `reason`. A community
  publishes a policy room; others **subscribe** to it. The protocol stays
  **neutral** — it models the data but does *not* interpret it or decide; the
  subscriber decides locally. **This is structurally FederLoom's model** (shared
  list + local decision = "lists are aids").
- **Trust = social, by design.** MSC2313 explicitly assumes *"don't use it if you
  don't trust the creator"* and defers verifiable trust + reputation metrics to
  future work.
- **MSC3845 — "expanding policy rooms to reputation" (still a DRAFT).** Proposes
  sharing an opinion of an entity as a number. The review thread is stuck on
  exactly FederLoom's problems: **how to combine lists with different scales**
  (add vs. average), severity (annoying vs. CSAM), threshold ambiguity.
- **Draupnir** (active successor to Mjolnir; NLnet/NGI-Zero funded) operationalises
  this: subscribe to community-curated policy lists so *adjacent communities warn
  and protect each other* — federated blocklists in production. **MSC4284 policy
  server** is newer server-side filtering, still research-phase.

**What FederLoom borrows.**
- The **signing-key + rotation/revocation + cross-signing** model — benchmark
  invite/fingerprint/trust-weight against it (battle-tested).
- The **MSC2313 data shape** (`entity` + `recommendation` + `reason`) is worth
  mirroring for conceptual interop — FederLoom's IP/score/reason is the same idea.
- The **neutrality principle** ("model, don't decide") = FederLoom's "lists are aids".

**What FederLoom does differently — and this is the key claim.**
- FederLoom supplies the **verifiable-trust + score-aggregation layer Matrix left as
  future work**: diversity-weighted corroboration, asymmetric decay, structural
  anti-poisoning, and a defined aggregation rule — i.e. an answer to the MSC3845
  score-combination problem.
- On-demand query vs. full replication; IP-reputation scope vs. chat abuse.

**Free design review.** The MSC3845 thread is a ready-made catalogue of the pitfalls
in combining reputation across sources — FederLoom should cite it when justifying
its own aggregation rule (see proposed spec §8 change).

**Collaboration angle (Q3 resolved → yes, after this research).** The Draupnir /
policy-list / MSC3845 community is solving the same problem in an adjacent domain
and is **NLnet/NGI-Zero funded** — relevant both as prior art FederLoom won't
embarrass itself on, and as a potential ally *and funding path* (ties into the
research-proposal thread). **Recommended:** open a low-key conversation referencing
MSC3845's open score-combination question with FederLoom's approach as one answer.

---

## Open Cloud Mesh (OCM) / Nextcloud

**What it is.** The server-to-server federation standard behind Nextcloud/ownCloud
file sharing (the colleague's "Nextcloud" pointer resolves to OCM).

**Trust model.** Admin-curated **trusted servers** lists + an **invite flow** to
establish server trust, after which users share across instances. Trust is
**pairwise, binary, manual**.

**What FederLoom borrows.**
- The **invite → trusted-server flow** is production-proven and close to FederLoom's
  `federation.invite` + fingerprint mechanism — validates that approach at scale.
- The **stay-narrow-and-additive** philosophy (OCM is just the sharing protocol).

**What FederLoom does differently.**
- Graded trust weights + decay + earned data-reputation vs. binary trusted/not.

**Note.** Weakest *threat-intel* analogue, strongest *server-trust-primitive*
analogue. Lesson is narrow but real.

---

## System profile & applicability weighting (Q5 — new FederLoom feature)

Q5 reframed the SBOM idea away from deep CVE-matching toward a **system
profile / role**: *what is this peer's system for* (webserver, mail, ssh, …), and
*which rules + score-weights should it apply*. The SBOM is a **semi-automated
matchmaker** that derives/refines that profile and the rule selection — it does not
need to be shared.

Resulting design (proposed; see spec change list):
- **Local system profile** — declared role(s) + optional SBOM-derived refinement.
  **Strictly local**, never federated (same invariant as the local-only whitelist;
  an SBOM/profile is a map of one's own attack surface).
- **Attack-vector / target-service descriptor on the wire** — an Event optionally
  states which service class was attacked (ssh / smtp-auth / web-login / …). This
  is coarse and largely *already implied* by the existing `reason` / `port_class`
  evidence fields, so it is an extension, not a new leak category. Could reuse STIX
  `attack-pattern` vocabulary for interop.
- **Applicability weighting** — when *consuming* a signal, weight it by how relevant
  the attacked service is to the local profile. An ssh-bruteforce signal weighs
  more for an ssh-exposed peer. This is a **local, consume-time** transform: it does
  **not** change the shared reputation, so it preserves federation consistency
  while letting each peer act on what matters to it.

This is the cleanest expression of the "relevance-weighted reputation" synthesis:
`effective weight = corroboration × source-trust × local-applicability`.

---

## Federation import model: evidence, not scores (aggregation → resolved: option b)

Cross-subnet score combination (the MSC3845 problem) is resolved by **not sharing a
combined score at all**. FederLoom imports **evidence**; every node **recomputes its
own score locally** under its **own adjustable, rule-based** "local truth". The
trust-discount becomes an **evidence weight** (per source/subnet), not a score
multiplier. Cleanest fit for "local view is truth", and it sidesteps cross-scale
ambiguity entirely.

Two consequences that must be designed deliberately:

- **Scaling reconciliation (vs. §11) — the main tension.** Importing *raw* events
  would resurrect the firehose. Reconcile by importing **structured evidence
  aggregates** (per IP: which sources/subnets/ASNs reported, counts, reasons,
  diversity, time-window) — lighter than raw events, richer than an opaque score —
  fetched **on-demand** for IPs that actually contact you (DNSBL-style). Raw events
  stay optional (observability plane). Evidence must carry enough **provenance /
  diversity metadata** for local corroboration (§4.2) to still work — ties into the
  existing `origin_trace` / `subnet_id` fields.
- **Rule-safety floor (resolved — reframed as local vs. remote).** Full operator
  sovereignty: the safety levers are the **whitelists** and the **peer/federation
  trust weights**, both already tuneable — there are **no hard floors against the
  operator**. The real invariant is **against the network**: no imported evidence,
  peer signal, or federation may *force* a local block, *force* a whitelist change,
  or *force* a trust change — remote input is always **advisory**; only local rules /
  config decide. Ship **safe defaults** (diversity-weighting + decay + ground-truth);
  tuning below them is the operator's own risk, clearly communicated. This honours
  "lists are aids" while still blocking network-level poisoning (the network can only
  ever *recommend*).

This makes FederLoom's **rules engine the core local primitive**: imported evidence
+ local profile (applicability) + reason codes + decay → local score/action, all
rule-driven and operator-adjustable above the floor.

- **MISP:** TLP / distribution-level / sharing-group vocabulary.
- **STIX:** `confidence` + `valid_until` + indicator vocabulary; export for interop.
- **Matrix:** signing-key model, rotation/revocation, cross-signing; study policy-list prior art.
- **OCM/Matrix:** invite-and-verify trust flow (already have it — benchmark vs. theirs).

## Interop opportunities (positioning as complementary)

- MISP import/export adapters (`ingest.Source` / `enforce.Sink`).
- STIX 2.x export of scores (ecosystem credibility).
- Explore the Matrix moderation/reputation community as fellow travellers.

## Decisions (resolved this round)

- **Q1 STIX/TAXII** → **egress/client export** (publish to downstream SIEM/TIP), not
  internal schema. Borrow `confidence`/`valid_until` vocabulary.
- **Q2 MISP** → **ingest/input** adapter, **post-MVP**. (MISP in, STIX out.)
- **Q3 Matrix** → researched (MSC2313 social-trust; MSC3845 reputation still draft;
  Draupnir in production). **Recommendation: yes, reach out** — adjacent problem,
  NLnet/NGI-Zero funded, possible ally + funding path.
- **Q4 novelty** → stronger honest claim adopted: "the verifiable-trust +
  aggregation layer Matrix deferred" + applicability weighting (see honesty box).
- **Q5 SBOM** → reframed as **system profile + applicability weighting** (new
  feature; section above).

## Remaining open questions

**Resolved this round:**
- **STIX/TAXII egress** → **poll model via the existing REST-API** (TAXII-server
  style, downstream polls). No push connector for now.
- **MSC2313 shape** → **future feature**, repurposed for **shareable
  peer/federation poison-reputation**: use the `m.policy.rule.server`-style shape to
  signal "this peer/federation is poisoning" and tune bad sources out network-wide
  (advisory, not forced).
- **Rule-safety floor** → **reframed local-vs-remote** (see section above): operator
  sovereign over tuneable whitelists + peer/federation trust; remote can only
  recommend, never force; safe defaults + tune-at-own-risk.

**Resolved — evidence-aggregate granularity.** A minimal evidence record carries:
- **Source** — the attacking IP (IPv4 *and* IPv6).
- **Target as abstract scenario** — e.g. `ssh-brute-force`, drawn from the
  reason-code catalogue; **no concrete ports** (privacy + abstraction). The scenario
  is the **join key**: corroboration scoring ↔ SBOM/profile applicability ↔ rules ↔
  STIX `attack-pattern` at egress. One concept, quadruple duty.
- **Timestamp** (date/time) — feeds decay + corroboration time-window.

Two additions required for it to actually work (caveats):
- **Diversity buckets for §4.2.** The above describes the *attack*; corroboration
  also needs *reporter diversity*. Add **pseudonymised diversity buckets**
  (ASN / region / subnet, from existing `origin_trace` / `subnet_id`) — counts of
  *distinct independent reporters per bucket*, never reporter identity. This is what
  lets diversity-weighting survive the evidence import.
- **IPv6 prefix granularity.** Single-`/128` reputation is near-useless (an attacker
  owns 2^64 addresses in one `/64`); corroboration would never trigger. Normalise
  IPv6 sources to a **prefix** (default `/64`, configurable) as the reputation unit.

> **Scenario taxonomy becomes load-bearing.** Scenarios are now the join key across
> wire, scoring, SBOM, rules, and egress — so the reason-code/scenario catalogue
> needs stable governance (who adds a scenario, how granular) and a fixed mapping to
> STIX `attack-pattern`.

**All brainstorm questions are now resolved.** Remaining work is consolidation into
`spec.md`.

**Noted future feature — source-reputation layer.** Sharing "this peer/federation is
a poisoner" is itself a poisoning vector (mark a *good* federation as bad → tune it
out). It must (a) be subject to the same structural defenses (diversity-weighted,
ground-truth-anchored, trust-weighted) as IP signals, and (b) stay **advisory** —
each node applies it through its own tuneable trust, never as a forced global ban.
This is a **meta-reputation layer**: reputation of *sources*, not just IPs. Maps
cleanly onto MSC2313's `m.policy.rule.server`.

---

*Next: turn resolved items into spec change-list entries and design notes; replace
the remaining [VERIFY] (OCM) with a citation; condense the TL;DR into the README's
positioning paragraph; open the Matrix/MSC3845 conversation.*
