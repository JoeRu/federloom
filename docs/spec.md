# Specification: Decentralized P2P Reputation Blocklist

**Working title:** *FederLoom* / https://github.com/JoeRu/federloom
**Status:** Current implementation in progress / current state
**Primary use case:** Shared defense through shared information / https://github.com/JoeRu/Mailcow-Crowdsec-Override
**Date:** 2026-07-07

---

## 1. Objective

A decentralized peer-to-peer network in which servers (initially: mail servers) report
observed attacks and jointly build up a **reputation score per IP address**.
Every operator remains sovereign: they consume the score and decide locally on
blocks based on **their own thresholds and whitelists**.

Inspired by Torrent/Tor/Ethereum concepts (gossip distribution, no central
single point of failure, economically/reputationally anchored trust), but
deliberately kept **without a real blockchain and without tokens/money** — as
simple as possible, as functional as necessary.

---

## 2. Guiding Principles (Leitprinzipien)

1. **Local sovereignty first.** The network delivers a *signal* (score), not
   a binding instruction. Thresholds, whitelists, and block actions are decided by the admin.
2. **Trust is earned, not given.** Trust grows slowly, falls quickly.
3. **Exploit structural attack properties.** Real attacks are *broadly
   distributed* and *independent*; poisoning is only so under high cost.
4. **Eventual consistency.** No global consensus needed — gossip/DHT-like
   propagation, local view is the truth.
5. **GDPR by design.** Legal basis: legitimate interest + automatic
   deletion via decay + responsibility resting with the local admin.
6. **Federated trust.** Trust reflects social/organizational structures
   (Mastodon model). No global trust compulsion; subnets and trust anchors
   are locally selectable and revocable.
7. **Lists are aids, not law.** The user can **override individual or all
   parameters**. Block and allow lists are "only" an aid —
   the final decision always rests locally.
8. **Locally sovereign, remote only advisory.** The operator may tune
   **everything** locally (whitelists, peer/federation trust, rules). The hard
   invariant applies **toward the network**: no imported signal, no peer, no
   federation may **force** a block, whitelist, or trust change upon
   you — remote input is always *advisory*. Secure defaults are shipped;
   loosening them is at your own risk. (Sharpens #1/#7 against network poisoning.)

---

## 3. Outputs (for Consumers)

Three levels of abstraction, depending on use case:

| Level | Description | Target audience |
|-------|--------------|------------|
| **Reputation score per IP** *(default)* | Normalized value (e.g., 0–100) | Most admins |
| **Ready-made blocklist** | Score + local threshold → drop-in for Fail2Ban/CrowdSec | "Plug & play" admins |
| **Raw events** | Individual reports with evidence | Power users / own analysis |
| **Federation feed export (STIX/TAXII)** | Client *reads* the federation and publishes events downstream (SIEM/TIP) | Integrators |

Decay and escalation are **functions of the score**, not hard on/off rules.

The STIX/TAXII export is **egress via the existing REST API** (poll model,
downstream polls — no push connector). STIX `confidence`/`valid_until` map to
score/decay; the scenario (§7.1) to STIX `attack-pattern`. **Our own reason
codes remain the source of truth**, STIX mapping only at the edge.

---

## 4. Defense Stack Against Poisoning (Core of the Design)

Chosen **lean stack** — three layers carry ~80% of the load:

### 4.1 Ground-truth Anchor Systems
- Sources of incorruptible truth, weighted maximally (trust ≈ 1.0). Two
  forms; detailed obligations per federation in §6.1:
  - **Dedicated honeypots:** IPs/mailboxes that are **never used
    legitimately** → every connection is malicious by definition →
    **zero false positives**.
  - **Real systems under load** with honeypot-like signals (spamtraps,
    auth attempts against non-existent accounts, unused ports).
- Dual use:
  - **Bootstrapping/genesis trust** (solves the chicken-and-egg problem of
    new nodes).
  - **Calibration:** nodes that fail to report known ground-truth attackers,
    or that whitelist ground-truth IPs, lose trust.
- **Operating models** (both documented, selectable):
  - **A) Centralized:** the project operates anchors + signs genesis peers →
    simpler start, clear trust anchor, but central dependency.
  - **B) Decentralized:** volunteers operate anchors, whose status is
    attested within the network → more robust, but requires more complex verification.

### 4.2 Diversity-weighted Corroboration
- The score rises only once **N *independent* reporters** see the same IP.
- Independence counts, not count: weighting by **diversity of sources**
  (different ASNs, countries, trust origin).
  - 10 reports from *one* ASN ≈ 1 vote.
  - 10 reports from 10 countries = a genuine signal.
- Exploits the structural property of real attacks (broad, independent);
  forging this requires expensive, widely distributed attacker infrastructure.

### 4.3 Reputation Stake with Asymmetric Decay
- **No money/tokens** — what is at stake is the **trust** built up over time.
- Trust formula (directional):
  `Trust = f(Age × demonstrated legitimate activity × consensus agreement)`
  - **Important:** age *alone* is Sybil-vulnerable (*patient Sybil*: run a
    node well-behaved for 6 months, then activate it in a coordinated
    fashion). Age is therefore only counted **coupled with** activity and
    consensus agreement.
- **Asymmetry as security:** trust rises **slowly**, falls **quickly** on
  anomaly or dispute (protection against hijacked high-trust nodes that
  suddenly report e.g. `8.8.8.8`).

### 4.4 Anti-trust / Dispute Feedback (Supplementary)
- **Local whitelist = negative, trust-weighted vote.** If many admins
  whitelist an IP, that is a strong "legitimate" signal.
- If a node repeatedly reports IPs that are broadly whitelisted, **its own
  trust** drops → poisoning damages the poisoner.
- **Caution, counter-attack:** mass whitelisting by Sybils could protect
  real attackers → whitelist votes need **the same diversity/trust
  weighting** as block votes.

> **Optional / later expansion stage (not in the lean stack):**
> Proof-of-work per report as a flood brake; web-of-trust with vouching;
> reputation slashing; structured plausibility checking of evidence.

### 4.5 Applicability Weighting (Local, Consume-time)
- At **consumption** time, a signal is weighted by how **applicable** the
  attacked service is to the *own* system (system profile §7.6, possibly
  SBOM-derived). An `ssh-brute-force` signal weighs more for an
  SSH-exposed peer.
- **Soft down-weight, not a hard filter** (default): services change,
  attackers pivot, and the IP remains valuable for corroboration. Hard
  filtering only as an optional local policy.
- **Purely local transformation:** does not change the *shared* reputation
  → federation consistency is preserved while each peer reacts to what is
  relevant to it.
- Resulting local formula:
  `effective weight = corroboration × source trust × local applicability`.

---

## 5. Federation, Trust Anchors & Subnets

Shifts the system from *one* global trust graph to **federated trust
domains** — consistent with Leitprinzip 4 (local view is truth) and the
**Mastodon model** of federated social networks with their own trust instruments.

### 5.1 Trust Anchor List (Signature-based)
- Locally curatable list of trustworthy **signature keys** (trust anchors).
- A report/score from an anchor — or from someone vouched for by an anchor —
  receives **increased weight**.
- The project can provide/distribute trustworthy signatures through
  **organizational measures**, e.g.:
  - signed "known good operators",
  - ground-truth anchor operators (bridge to §4.1),
  - curated CERT/threat-intel feeds.
- **Critical — against re-centralization:** anchors must be locally
  **addable AND removable**. Project anchors are a sensible **default, not a
  mandate**. Otherwise the project becomes a central authority through the
  back door.
- **Key lifecycle:** rotation, revocation (revocation list or short validity
  periods), handling compromised anchor keys (details in §6.3).
- **Unifying primitive:** honeypot/ground-truth anchors (§4.1) and the
  never-block set (§10) are special cases of this anchor mechanism — same
  logic, different weight and different source.

### 5.2 Own Subnets (Federation, Mastodon Model)
- Operators can span their own **trust domains/subnets** with their own
  trust roots and their own governance.
- **Mastodon analogy:** every instance moderates itself but federates selectively.
- Modes of operation of a subnet:
  - **Isolated:** own trust, no import (e.g. company-/association-internal network).
  - **Federated:** **evidence aggregates** (not finished scores) from other
    subnets are imported and **recomputed locally by rule**. The former
    trust discount becomes an **evidence weight** per source/subnet. This
    eliminates the problem of combining foreign score scales (cf. Matrix
    MSC3845, which is stuck as a draft on exactly this — see `docs/prior-art.md`).
- **Federation mode** (like Mastodon):
  - **Allowlist / default-deny:** only explicitly trusted subnets.
  - **Blocklist / default-allow:** all except those explicitly blocked.
  - *Recommendation:* federation as default (with discount), isolation as a
    deliberate exception — otherwise coverage fragments before the network
    effect can take hold.
- **Defederation as a security mechanism:** a malicious/compromised subnet
  gets "defederated" like a bad Mastodon instance → the Sybil response at
  the **subnet level**.
- **Caution, feedback loop:** mutual import (A↔B) can let the same
  information be counted multiple times → **origin tracking** per report or
  a strictly decaying discount over federation hops is needed (Problem K).

### 5.3 Resulting Model
- Instead of *one* global truth, a **mesh of trust domains** that mirrors
  social and organizational trust structures.
- Every node/subnet computes its **own** score from:
  `own evidence + imported (evidence-weighted) foreign evidence + anchor signals`,
  combined locally via the rule engine into an **own** score.

---

## 6. Organizational Obligations per Federation (Onboarding & Repo Documentation)

Every federation/group must initially define these points; joining users
require a sensible way to connect to them. **The repository MUST explain
this clearly** (a prominent onboarding guide, not just a reference appendix).

### 6.1 Define Ground-truth Anchor Systems
- Registration of the corresponding signatures as **highly weighted trust
  anchors** (§5.1).
- Source, either:
  - **Dedicated honeypots** — zero false positives, but extra infrastructure.
  - **"Real systems under load"** — see real attack patterns, no extra box needed.
- **Critical caveat:** a real system does **not** have the
  zero-false-positive property (it also receives legitimate traffic).
  Recommendation: do not treat the whole system as ground truth, but rather
  the **honeypot-like signals within the real system** that preserve the
  guarantee:
  - spamtrap addresses (mailboxes never actually used),
  - auth attempts against non-existent accounts,
  - connections to unused/closed ports.

### 6.2 Maintain the Bulk Whitelist (Central + Local Truth)
- Federation-wide whitelist (corresponds to the never-block set, §10) is
  maintained centrally.
- Always supplemented with the **"local truth"** per installation, ideally
  via an **install script** that automatically reads out and lists:
  - own public IP(s),
  - gateways,
  - own/configured DNS servers,
  - local Docker IP ranges (e.g. bridge networks 172.16.0.0/12),
  - RFC1918 / loopback.
- **Mandatory separation** (privacy, Problem E):
  - **Local-only whitelist:** local infrastructure — **never shared with
    the network** (irrelevant to others + leaks topology). Only suppresses
    local blocks.
  - **Shared whitelist votes:** deliberate "this public IP is legitimate"
    signals (trust-weighted, §4.4).
- **Caveat, auto-detection:** must not whitelist too broadly (e.g. entire
  public provider ranges) → conservative, only unambiguously local ranges.
- → addresses **Problem F**.

### 6.3 Key Management
- Define **who issues and vouches for anchor/node keys**.
- Rotation and revocation policy: distribution of the revocation list,
  validity periods.
- Procedure for **compromised keys**: fast revocation + trust reset.
- → addresses **Problem J**.

### 6.4 Overarching Principle (Reminder)
In the end, the user can **override individual or all parameters**. The
lists (block & allow) are "only" an aid — see Leitprinzip 7. Onboarding
must make this explicit so that nobody mistakes the federation defaults for binding.

---

## 7. Data Model (Draft)

### 7.1 Report (Event)
| Field | Description |
|------|--------------|
| `ip` | Cleartext IPv4 (single address) / IPv6 **prefix-normalized** (default `/64`, configurable — a single `/128` never corroborates). Hashing rejected (§9). |
| `scenario` | Abstract attack **scenario** from the reason-code catalog (e.g. `ssh-brute-force`, `smtp-auth-bruteforce`). **Join key**: scoring ↔ SBOM/profile ↔ rules ↔ STIX `attack-pattern`. **No concrete ports.** |
| `timestamp` | Time of observation |
| `port_class` *(optional, deprecated)* | Coarse port class; superseded by `scenario`, to avoid leaking service details |
| `reporter_id` | Pseudonymous node ID (cryptographic key) |
| `signature` | Reporter's signature |
| `subnet_id` | Origin subnet/trust domain (for federation, §5) |
| `origin_trace` | Origin chain (against federation feedback loops, §5.2) |

### 7.2 Aggregated Reputation Entry per IP
| Field | Description |
|------|--------------|
| `ip` | Address |
| `score` | Current normalized reputation score (**per trust domain!**) |
| `corroboration` | Count + diversity of independent reporters |
| `first_seen` / `last_seen` | For decay |
| `reasons[]` | Aggregated attack reasons |
| `disputes` | Whitelist/anti-trust votes |

### 7.3 Trust Anchor Entry
| Field | Description |
|------|--------------|
| `key_id` | Anchor's public key |
| `label` | Designation/origin (e.g. "Mailcow project", "Spamtrap cluster DE") |
| `weight` | Local trust weight |
| `valid_until` | Validity (for rotation/revocation) |
| `source` | `project-default` \| `self-added` \| `subnet` |

### 7.4 Whitelist Entry
| Field | Description |
|------|--------------|
| `ip_or_range` | Address/CIDR |
| `scope` | `local-only` (never shared) \| `shared-vote` (trust-weighted) |
| `source` | `install-script` \| `manual` \| `federation` |

### 7.5 Evidence Aggregate (Federated Import Type)
What is shared between subnets and **recomputed locally** (option b, §5.2).
Lighter than raw events, richer than an opaque score.

| Field | Description |
|------|--------------|
| `ip` | Source (IPv4 single / IPv6 prefix-normalized) |
| `scenario` | Attack scenario (§7.1) |
| `window` | Time window (for decay + corroboration freshness) |
| `diversity_buckets` | **Pseudonymized** counters of distinct *independent* reporters per bucket (ASN / region / subnet; from `origin_trace`/`subnet_id`) — **never reporter identity**. Carries §4.2 across the import. |
| `evidence_weight` | Source/subnet weight (formerly trust discount) |

> Fetched **on demand** (DNSBL-style) for IPs that actually contact you — raw
> events remain optional (observability plane). Reconciliation with §11.

### 7.6 System Profile (Local, Never Federated)
Drives applicability weighting (§4.5) and rule selection.

| Field | Description |
|------|--------------|
| `roles[]` | What the system is for (`mail`, `web`, `ssh`, …) — declared |
| `sbom_derived` | Whether/to what extent refined from a local SBOM (semi-automatic matchmaker) |
| `applicable_scenarios[]` | Scenarios relevant to this system |

> **Invariant:** the profile **and** the SBOM remain **strictly local** (an
> SBOM is the map of one's own attack surface) — same family as the
> `local-only` whitelist.

---

## 8. Score Dynamics

- **Escalation:** repeated attacks / broader corroboration → score rises
  (super-linearly under high source diversity).
- **Local recomputation from evidence (core mechanic).** The score is
  **not** an imported foreign value: every node combines its **own +
  imported evidence aggregates** (§7.5) via the **rule engine** into its own
  score. The rules are operator-adjustable (on top of the defaults);
  remote input remains advisory (§2 #8).
- **Effective weight** `= corroboration (diversity-weighted) × evidence
  weight (source) × local applicability (profile, §4.5)`.
- **Decay (degeneration):** without new reports the score falls toward 0 over time.
  - Simultaneously functions as the **GDPR deletion period** (see §9).
  - Half-life is a **critical tuning parameter**:
    - too short → the list becomes useless
    - too long → punishes innocent IP successors (DHCP/CGNAT)
  - **Open:** concrete half-life, possibly dependent on attack type.

---

## 9. GDPR / Legal

**Correct framing (decisive for project trust):** Not "an IP is not PII" —
that does not hold up legally. Rather:

> **"IP = personal data, processed on the basis of legitimate interest
> (berechtigtes Interesse) in network/information security (Art. 6(1)(f),
> Recital 49), with built-in deletion via decay (Art. 17) and local accountability."**

**Rationale / against the original assumption:**
- **CJEU *Breyer* (C-582/14):** even dynamic IPs are personal data as soon
  as they are legally identifiable via a third party (ISP). The project
  delivers *more* context (IP + time + behavior), not less → firmly within
  the scope of personal data.
- **Art. 10 GDPR:** data about (alleged) criminal offenses enjoys
  *increased* protection, not less. These are **alleged** attacks → false
  positives (CGNAT neighbors, hijacked hosts, newly reassigned IPs) are the
  actual GDPR core concern.

**Hashing as anonymization — rejected:**
- The IPv4 space (2³², ~4.3 billion) is trivially reversible via rainbow
  table → SHA-256(IP) is **pseudonymization, not anonymization** (Recital 26
  → still PII).
- Would have gained almost nothing legally, but would technically destroy
  CIDR aggregation + decay. → **Cleartext IPs on the wire.**

**Built-in compliance mechanisms:**
- Decay = automatic deletion / storage limitation.
- Local thresholds + whitelist = the controller is the admin, not the network.
- Legitimate interest in network security = strongest legal basis.

---

## 10. Mandatory Protection List (Never-Block-Set)

**Secure default, locally tunable, remote-immutable.** Prevents naive admins
from locking themselves out, but is **not** a hard floor against the
operator (whitelists are tunable, §2 #8) — the untouchability applies only
**toward the network**: no remote signal can change the set. Recommended
default entries:
- RFC1918 / private ranges
- Root DNS, public resolvers (e.g. 8.8.8.8, 1.1.1.1)
- Large mail provider ranges (Google, Microsoft/Outlook)
- Cloudflare and similar CDN/infra ranges

Maintained per federation (§6.2) and can be modeled as a special case of a
project trust anchor (§5.1). Locally supplemented with the "local truth"
(install script).

---

## 11. Scaling, Performance & Data Flows

Two scaling risks in large networks: (a) the list of reported IPs becomes
too large to filter with meaningfully; (b) real-time gossiping of every
event creates a traffic/CPU avalanche. **Core inversion:** the global list
is **not materialized locally** (the "torrent model" is rejected) —
instead, **on-demand querying** (DNSBL principle) + a compact local
pre-filter. This solves both problems at once.

### 11.1 Order of Magnitude (Reality Check)
- Actively malicious IPs worldwide: **single-digit millions** at any given
  time (cf. CrowdSec ~1–3 million, Spamhaus), **not** the 4.3-billion IPv4 space.
- Constantly rotating → decay (§8) bounds the DB from above (garbage collector).

### 11.2 Three-plane Architecture (Decoupling)
| Plane | Content | Property |
|-------|--------|-------------|
| **Data plane** (enforcement) | only IPs above the local threshold that actually contact you | lean, O(1) lookup |
| **Control plane** (reputation) | score DB / sync | eventual consistency, batched, low priority |
| **Observability plane** (firehose) | real-time event stream for attack-wave monitoring | **opt-in, default OFF** |

The normal admin only loads the data + control plane; the live feed is
optionally switchable on for SOC/research (observation of attack waves).

### 11.3 Controlling List Size
- **DB ≠ enforcement set:** the heavy reputation DB is not what the
  firewall sees. The **local threshold is the natural filter** — you
  consume a score, you don't import a global list. Active set = thousands,
  not millions.
- **The enforcement backend is the actual bottleneck (footgun):**
  - **Wrong:** one `iptables` rule per IP (Fail2Ban style) → **O(n) per
    packet**, melts down at tens of thousands of entries.
  - **Right:** `ipset`/`nftables` hash sets → **O(1)**, handle hundreds of thousands+.
- **Bloom filter as a pre-filter:** 1 million IPs @ 1% FP ≈ ~1.2 MB. The
  common case ("is this IP unsuspicious?") is answered locally in µs with
  "no"; only hits require a real lookup.
- **CIDR aggregation (optional):** condense repeat-offender subnets into
  ranges → fewer entries. **Trade-off:** collateral damage to neighbors
  (tension with Problem D, IP ≠ identity).

### 11.4 Controlling Traffic
- **On-demand query (DNSBL model):** query reputation via DHT lookup only
  when an IP actually contacts you + a local TTL cache. You only query what
  concerns you → no continuous traffic.
- **Aggregation at the edge:** don't gossip 500 individual events, but
  rather periodic summaries ("IP X: 500 auth attempts/5 min"). Granularity
  traded for bandwidth.
- **Relay hierarchy instead of full mesh:** full meshing is O(N²).
  Aggregator/relay nodes per federation consolidate and distribute (cf. Tor
  directory authorities / Mastodon relays) — **the federation is the
  natural aggregation boundary**.
- **Signature verification:** per-event verification is CPU-expensive in a
  large network → batch verification / verification of aggregated digests
  instead of every single event.

### 11.5 Good-neighbor Principle (User Perspective)
> **The protection mechanism must never itself become the performance problem.**
- **Resource budget:** configurable CPU/bandwidth limit, low priority
  (`nice`/cgroups).
- **Graceful degradation / load shedding:** if the box itself is under an
  attack wave, the daemon defers third-party verification/gossip, protects
  only locally, and synchronizes later (local protection takes precedence
  over network contribution).
- **Sync mode selectable:** push (full sync, small federations) ↔
  pull-on-demand (large networks) ↔ hybrid.

---

## 12. Open Problems & Risks

| # | Problem | Status |
|---|---------|--------|
| A | **Poisoning** fundamentally never "solved", only made expensive/conspicuous | mitigated via §4 |
| B | **Bootstrapping/chicken-and-egg** for new low-trust nodes | solved via ground-truth genesis (§4.1) |
| C | **Verifiability** of individual reports (high-trust node hacked) | mitigated via corroboration + fast trust decay |
| D | **IP ≠ identity** (CGNAT, DHCP) → decay tuning | open (half-life, §8) |
| E | **Reporter privacy** (leaks infra topology, whitelist preferences) | partly solved via local-only whitelist (§6.2); Tor-like submission vs. Sybil accountability **open** |
| F | **Maintaining the never-block set + local truth** | addressed via §6.2 (install script); governance open |
| G | **Ground-truth verification** in the decentralized model B | open |
| H | **Mass whitelist attack** to protect real attackers | mitigated via weighted whitelist votes (§4.4) |
| I | **Re-centralization** through blanket adoption of project anchors | mitigated via locally removable anchors (§5.1), default ≠ mandate |
| J | **Key management** (rotation, revocation, compromised keys) | addressed via §6.3; detailed format open |
| K | **Federation feedback loop & fragmentation** (double-counting A↔B; diluted network effect) | mitigated via origin tracking/hop discount (§5.2) |
| L | **Malicious/compromised subnet** | mitigated via defederation (§5.2) |
| M | **Real system as ground truth** → loss of the zero-false-positive property | mitigated via honeypot semantics within the real system / spamtraps (§6.1) |
| N | **Overly broad auto-whitelist** via the install script | mitigated via conservative detection (§6.2) |
| O | **List size** overwhelms the filter | mitigated via DB≠enforcement-set, threshold filter, Bloom, decay (§11.3) |
| P | **Traffic avalanche** in a large network (real-time gossip) | mitigated via on-demand/DNSBL, aggregation, relay hierarchy (§11.4) |
| Q | **Enforcement backend O(n)** (Fail2Ban style) melts down | solved via ipset/nftables O(1) (§11.3) |
| R | **CPU load from signature verification** in a large network | mitigated via batch verification + load shedding (§11.4/§11.5) |
| S | **Sybil via discovery** — many DHT phantoms flood the stranger pool | mitigated via the existing `strangerCap` per IP (§4.2/§4.3) |
| T | **Advertiser privacy** — DHT entry leaks IP + peer ID | mitigated via `advertise: false` opt-out (§14.1/§14.5); onboarding obligation |
| U | **Source reputation as meta-poisoning** (marking a *good* federation as a "poisoner") | mitigated: the same structural defenses as IP signals + remains advisory, never a forced global ban (future feature, §13) |
| V | **IPv6 `/128` reputation useless** (attacker owns 2^64 addresses per `/64`) | solved via **prefix normalization** (`/64` default, §7.1) |
| W | **Rule misconfiguration** reduces local protective effect | mitigated via secure defaults + the remote-advisory invariant (§2 #8); protective rules marked in the UI |
| X | **Evidence import volume** (option b) threatens §11 leanness | mitigated via on-demand evidence aggregates (§7.5) instead of raw events/opaque scores |

---

## 14. Federation Discovery

The swarm is only effective above a critical mass. The manual invite/join
protocol (§5.2) produces highly trustworthy federations, but also
bootstrapping friction: a node without existing contacts does not
participate in the network. Discovery solves this by letting nodes find
each other automatically — **without presupposing an existing trust
relationship** and without bypassing the trust model.

### 14.1 Two Opt-out Flags (Both Default: On)

| Flag | Function |
|------|----------|
| `discovery.advertise` | Publishes this node at the DHT rendezvous point |
| `discovery.discover` | Actively searches the DHT for further peers |

Both independently configurable (local sovereignty, Leitprinzip 7).
Operators who want complete privacy (e.g. company-internal networks) set
`advertise: false` and rely on manual invite/join.

### 14.2 Discovery Mechanism

**Primary — DHT rendezvous (decentralized):**
Nodes register under a fixed key (`/federloom/v1/peers`) in the existing
Kademlia DHT. No project server needed; uses the already-established
transport layer.

**Fallback — signed relay list (cold start):**
A project-signed, versioned JSON file with known bootstrap/relay nodes
(analogous to Tor directory authorities). Shipped with the release, locally
overridable. Only used when the DHT is not yet reachable (fresh install, no
peers present).

The relay list follows the anchor principle (§5.1): project-signed as a
sensible **default, not a mandate**. Operators can add their own bootstrap
lists and remove the project list.

### 14.3 Trust of Newly Discovered Nodes

Newly discovered (not invited) nodes receive `trust.stranger_weight` — the
same value as any non-anchored reporter. The existing `strangerCap` per IP
limits the coordinated Sybil contribution of many discovered strangers
(Problem S, §12).

To upgrade a discovered node: `federloomctl trust import` (manual
vouching). The trust model remains unchanged; discovery merely extends the
pool of reachable nodes.

### 14.4 Interaction with Federation Mode

The existing `federation.mode` (allowlist / blocklist, §5.2) applies
unchanged. Discovery delivers more strangers into the pool; their weight is
capped by the stranger mechanism. An `allowlist` node connects to
discovered peers but weights their reports only with `stranger_weight`.

### 14.5 Privacy Notice

`advertise: true` publishes this node's IP address and peer ID in the DHT —
**publicly visible to every DHT participant**. Operators in
privacy-sensitive environments should set `advertise: false`. The
onboarding documentation must explain this prominently.

---

## 12a. Implementation Traceability (2026-07)

Honest status of each design area in the current codebase. This table — not the
§13 "Nächste Schritte" list — is the source of truth for what is live.
`DONE` = implemented and tested · `PARTIAL` = present but incomplete/inert ·
`PLANNED` = designed, not yet built (remediation sub-project in parentheses).

| Spec § | Area | Package | Status |
|---|---|---|---|
| §4.1 | Ground-truth anchors | `internal/trust`, honeypot/spamtrap ingest | DONE |
| §4.2 | Diversity-weighted corroboration (ASN/geo) | — | PLANNED (D) |
| §4.3 | Asymmetric decay | `internal/reputation` | DONE |
| §4.4 | Dispute / anti-trust votes | — | PLANNED (E) |
| §4.5 | Applicability weighting | — | PLANNED (E) |
| §5.1 | Trust anchors (Person keys, peer certs) | `internal/trust`, `internal/identity` | DONE |
| §5.2 | Federation import / discount / origin-trace | `internal/node`, `internal/transport`, `internal/repquery` | PARTIAL — origin-trace + per-hop discount (E1); evidence import via query path DONE (E2); gossip-side evidence import PLANNED |
| §7.1 | Event model | `pkg/proto` | DONE — `port_class` deprecated-retained |
| §7.1 | IPv6 `/64` prefix normalization | `internal/netutil`, `internal/node`, `internal/enforce` | DONE |
| §7.2 | ScoreEntry aggregate | `pkg/proto` | RESERVED — replaced by EvidenceAggregate (E2); slated for C1 removal |
| §7.5 | EvidenceAggregate (federated import type) | `pkg/proto`, `internal/repquery` | DONE — the on-demand query answer, recomputed locally (E2) |
| §7.6 | System profile / SBOM | — | PLANNED (E) |
| §8 | Score dynamics (logistic accumulation, decay) | `internal/reputation`, `internal/rules` | DONE |
| §9 | GDPR framing (cleartext IP, decay = deletion) | `internal/store` (TTL) | DONE |
| §10 | Never-block set | `internal/enforce` | DONE — incl. public resolvers |
| §11.3 | O(1) enforcement (ipset/nftables) | `internal/enforce` | DONE |
| §11.4 | On-demand query / pull transport | `internal/repquery` | PARTIAL — read path via configured aggregators (E3); DHT/bloom + materialise-on-verdict PLANNED |
| §14 | Federation discovery (DHT + relay list) | `internal/discovery` | DONE |

## 13. Next Steps

> **Superseded (2026-07-10):** The sequencing now lives in
> [docs/roadmap.md](roadmap.md); the live status is in §12a. This list
> remains preserved as historical design context — several items (among
> them 5, 8, 10, 11, 15) have since been implemented.

1. Model the **decay half-life** (possibly per attack type) – Problem D.
2. Decide on **reporter privacy** (anonymity ↔ accountability) – Problem E.
3. Choose the **ground-truth operating model** (honeypot vs. real system + spamtrap; A/B) – §4.1/§6.1.
4. Define **score normalization & threshold defaults** for Mailcow.
5. Specify the **transport/gossip protocol** (DHT vs. gossip vs. hybrid).
6. **Federation semantics:** trust discount function, origin tracking,
   allowlist vs. blocklist default, defederation – Problems K/L.
7. Specify the **anchor key lifecycle** (format, rotation, revocation) – Problem J.
8. Build the **install script**: auto-detection of local truth → local-only whitelist – §6.2.
9. Write **repository onboarding documentation** that prominently explains §6 (founding obligations of
   every federation: ground-truth anchors, whitelist maintenance, key management, override principle).
10. Define the **enforcement backend**: ipset/nftables (not iptables-rule-per-IP) – Problem Q.
11. Decide the **sync model**: push vs. pull-on-demand (DNSBL) vs. hybrid; Bloom pre-filter – §11.
12. Specify **resource budget & load shedding** (CPU/bandwidth, graceful degradation) – §11.5.
13. Design the **observability plane** as opt-in (attack-wave monitoring, default off) – §11.2.
14. **Prototype order:** ground truth + diversity corroboration first (80%),
    then trust anchors, subnet federation last.
15. Implement **federation discovery**: DHT rendezvous + signed relay list
    as fallback; two opt-out flags (`advertise`/`discover`, both default on) – §14.
16. **System profile + applicability** (§4.5/§7.6): roles + SBOM matchmaker,
    soft down-weighting at consumption time.
17. **Evidence import model** (option b): `EvidenceAggregate` (§7.5), local
    rule recomputation (§8), diversity buckets, IPv6 prefix.
18. **STIX/TAXII egress** via the existing REST API (poll) – §3.
19. **MISP ingest adapter** (`ingest.Source`) – **post-MVP**.
20. **Source reputation layer** as a **future feature**: sharing "this
    federation is poisoning" (maps to MSC2313 `m.policy.rule.server`),
    advisory, structurally secured (Risk U).
21. **Scenario/reason-code catalog governance** + fixed mapping to STIX
    `attack-pattern` (scenario is now the load-bearing element across 5 layers).
22. Benchmark **key handling** against the Matrix signing-key model
    (optional) – see `docs/prior-art.md`.
23. Add **`docs/prior-art.md`** to the repo (positioning + honesty boundary).
