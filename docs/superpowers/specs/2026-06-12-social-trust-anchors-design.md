# Social Trust Anchors Design

**Date:** 2026-06-12
**Status:** Approved
**Spec references:** §5.1 (Trust-Anchor-Liste, signaturbasiert), §4.2 (Diversitäts-gewichtete
Korroboration), §7.1/§7.3 (Event, AnchorEntry), Invariants 1 & 6
**Touches the wire contract:** yes — `pkg/proto` gains a vouching certificate and
`SchemaVersion` bumps 0 → 1. Implementation MUST follow `.claude/skills/wire-protocol`.

## Goal

Implement the first real trust layer as a **cryptographic chain of trust**, exactly as
§5.1 describes ("eine Meldung von einem Anchor — oder von jemandem, den ein Anchor
**verbürgt** — erhält erhöhtes Gewicht"):

- A **Person** is a long-lived Ed25519 **identity key** (a human, e.g. "Jo").
- Jo's identity key **signs a certificate for each of his machines** binding that
  machine's libp2p peer ID to his identity.
- You **anchor Jo's identity public key once**, with a weight. Every machine Jo
  certifies inherits that trust automatically — including new machines he adds later.
- Certificates **travel on the wire** with each report, so a node anchors an identity
  and never has to enumerate or re-import machines.
- Un-anchored **strangers** are capped so a Sybil flood cannot push an IP past the
  block threshold.

**The Person is the diversity unit (§4.2):** corroboration counts distinct anchored
Persons, not peer IDs. Jo's three machines are one independent vote — cryptographically
proven, because each carries a cert chaining to the same identity.

This replaces the hardcoded `1.0` / `0.3` trust constants in
`internal/node/node.go:136/157` with a resolvable, operator-curated, signature-backed
model.

## Out of scope

- Dynamic node trust (§4.3 — trust auto-rising/falling with behaviour). Anchors are
  static human grants; you re-rate or remove a Person explicitly.
- Per-machine revocation lists. Revocation is handled by short `valid_until` on certs
  plus immediate Person-level removal. Revoking a *single* compromised machine of Jo's
  before its cert expires requires Jo to rotate (re-issue with new validity) — noted as
  a limitation, full per-peer revocation is future work.
- Dispute / whitelist votes (§4.4).
- Transitive vouching beyond one hop (Person vouches for another Person). One hop only:
  identity → peer.
- Project-default anchors (`source: "project-default"`). Only `self-added` here.

## Keys (three, distinct roles)

| Key | Lives where | Role |
|---|---|---|
| **Node libp2p key** `identity.key` | every node, `<store.dir>/identity.key`, 0600 | Stable peer ID across restarts. Required. |
| **Person identity key** `person.key` | only where the human signs certs, 0600 | The human "Jo". Signs peer-certs. Distinct from any machine so one compromised box does not burn the identity. Optional — only needed to be anchorable. |
| **Peer-cert** `peer.cert` | each vouched node, `<store.dir>/peer.cert` | Jo's identity signing "this peer ID is mine". The node attaches it to every Event it publishes. |

A solo operator nobody anchors needs only the node key; `person.key` and `peer.cert`
are opt-in infrastructure for being vouched.

## Wire contract change (`pkg/proto`)

`SchemaVersion` bumps `0 → 1` (still pre-release, but now carries vouching). New type:

```go
// PeerCert binds a node's libp2p peer ID to a Person identity (spec §5.1).
// Signed by the Person identity key; verified by anchoring the Person's public key.
type PeerCert struct {
    PeerID     string    `json:"peer_id"`     // libp2p peer ID being vouched for
    PersonKey  []byte    `json:"person_key"`  // Ed25519 public key of the Person identity
    ValidUntil time.Time `json:"valid_until"` // cert expiry
    Sig        []byte    `json:"sig"`         // Ed25519 sig by PersonKey over (PeerID‖PersonKey‖ValidUntil)
}
```

`Event` gains one optional field (additive; old nodes ignore it, new nodes treat its
absence as "stranger"):

```go
Vouch *PeerCert `json:"vouch,omitempty"` // present if the reporter is vouched by a Person identity
```

`Event.Signature` stays reserved/unused (future relayed events where transport-level
auth is unavailable). Vouching is the new mechanism; per-report signing is **not**
re-added because gossipsub already authenticates the publisher.

## Architecture

Five components, all control plane. `internal/enforce` is not touched.

### 1. `internal/identity` — node + person keys, cert issuance/verification

- Load-or-create the **node** Ed25519 keypair at `<store.dir>/identity.key` (0600);
  the libp2p host is built from it, so the peer ID is stable. swarmd refuses to start
  if the file is group/world-readable.
- Manage the optional **person** key at `<store.dir>/person.key` (0600).
- `IssueCert(personKey, peerID, validUntil) PeerCert` — sign a binding.
- `VerifyCert(cert PeerCert, now time.Time) error` — check `Sig` under `PersonKey`,
  check `now < ValidUntil`. (Anchoring of `PersonKey` is checked by `internal/trust`.)

### 2. `internal/trust` — anchor store + verified cert cache

- **Anchor store**: reads `<store.dir>/anchors.json`, a list of anchored Person
  identities (no machine enumeration):

```json
[
  { "person": "jo", "label": "Jo", "identity_pubkey": "ed25519:9f3c…",
    "weight": 0.9, "valid_until": "0001-01-01T00:00:00Z", "source": "self-added" }
]
```

  Hot-reloaded on mtime change (checked at most every 10s); no daemon restart to add,
  re-rate, or remove a Person.
- **Cert cache**: peer-ID → verified `(PersonKey, ValidUntil)` binding, populated both
  by on-wire certs and by local bundle import. Entries are re-checked against the
  anchor store and expiry on every `Resolve`.
- Single query used by the node:

```go
// Resolve returns the trust weight, the corroboration group (= Person name),
// and whether peerID is currently vouched by an anchored, non-expired Person.
func (s *Store) Resolve(peerID string) (weight float64, group string, anchored bool)
```

  Anchored & valid → Person weight (default `trust.anchor_weight` = 0.9), group =
  Person name. Otherwise → `trust.stranger_weight` (0.3), group `""`, anchored = false.

### 3. `swarmctl` — identity, certs, anchoring CLI

Manual identity-fingerprint exchange over any channel the operators already trust
(Signal, phone, in person). Anchor edits use temp-file + atomic rename; they work
whether swarmd is running or not.

```
# Jo, once:
swarmctl identity init --label "Jo"      # create person.key; auto-cert + install peer.cert for the local node
swarmctl identity show                    # print Jo's identity pubkey + fingerprint to share
swarmctl peer-cert <peer-id>              # sign an additional machine; prints a cert to install on that node
swarmctl trust export > jo.bundle         # optional offline bundle: identity pubkey + label + all peer-certs

# You, after verifying Jo's fingerprint out-of-band:
swarmctl trust add jo --identity ed25519:9f3c… --weight 0.9   # anchor Jo's identity (the only required step)
swarmctl trust import jo.bundle                                # optional: seed identity + certs offline
swarmctl trust set jo --weight 0.8 --label "Jo"               # manage the human in one place
swarmctl trust remove jo                                       # drop Jo and every machine he certified
swarmctl trust list                                            # grouped by Person, flags EXPIRED
swarmctl identity                                             # print this node's own peer ID
```

- The Person is the unit you manage: weight, label, and expiry live on the identity,
  not on individual peers.
- `trust add jo` is idempotent (re-running updates the entry).
- Anchoring your own identity warns and is a no-op (local events already run at 1.0).
- `weight` must be in (0, 1].
- swarmctl locates the data dir via the same `config.yaml` swarmd uses
  (`--config`, same default path).

### 4. Verified sender binding + vouch extraction — `internal/transport` + `internal/node`

gossipsub signs every message and verifies the publisher's identity on receipt. The
subscription handler surfaces the **verified publisher peer ID** alongside the decoded
`proto.Event`. The node then, per event:

1. **Drop** if `Event.ReporterID != verifiedPublisher` (spoof guard), log mismatch.
2. If `Event.Vouch == nil` → stranger path.
3. Else verify the vouch: `Vouch.PeerID == verifiedPublisher`,
   `identity.VerifyCert(Vouch, now)` passes, and `Vouch.PersonKey` is anchored in
   `internal/trust`. On success the cert is cached and trust resolves to the Person's
   weight/group; on any failure → stranger.

A vouched node attaches its installed `peer.cert` to every Event it publishes.

### 5. Capped-stranger corroboration — `internal/reputation`

`Record` becomes group/anchored aware:

```go
func (e *Engine) Record(ip, reason, reporterID string, trust float64, group string, anchored bool) (float64, error)
```

`store.ScoreRecord` (BadgerDB value — local storage, not wire format) gains:

- `Groups []string` — distinct anchored Person names that reported this IP.
- `StrangerContrib float64` — cumulative score points contributed by strangers.

Scoring:

- **Anchored reporter:** full logistic contribution
  (`trust × weightFor(reason) × (1 − score/100)`); its Person name is added to `Groups`
  if new.
- **Stranger:** same formula, but clamped so `StrangerContrib` never exceeds
  `trust.stranger_score_cap` (default 15). At the cap, further stranger reports update
  `LastSeen`/`Reasons`/`ReporterIDs` but add zero score.
- **Corroboration** = `len(Groups)` + 1 if any stranger reported, else 0.
- **Local ingest events unchanged:** trust 1.0, own peer ID, the node is implicitly its
  own anchored group.
- Decay, TTL, thresholds, enforcement untouched.

Worked example (block threshold 50, `ssh-auth-bruteforce` weight 10): Jo's three
machines (one cert chain, Person `jo`, weight 0.9) plus 100 Sybils all report one IP.
Sybils contribute ≤ 15 points total and count as 1 corroboration vote. Jo's machines
contribute ~9 points per report but count as **one** group. The IP crosses the threshold
only when a second anchored Person — or the operator's own honeypot — corroborates. One
compromised friend cannot cross it alone; neither can any number of Sybils.

## Config additions (`internal/config`)

```yaml
trust:
  anchors_file: ""          # default <store.dir>/anchors.json
  person_key_file: ""       # default <store.dir>/person.key
  peer_cert_file: ""        # default <store.dir>/peer.cert
  anchor_weight: 0.9        # default weight for a newly anchored Person
  stranger_weight: 0.3      # replaces the hardcoded 0.3 in node.go
  stranger_score_cap: 15    # max total score points strangers add per IP
```

All values operator-overridable (Invariant 1).

## Edge cases & failure behaviour

| Case | Behaviour |
|---|---|
| `anchors.json` missing | Empty anchor list; everyone is a stranger. Normal cold start. |
| `anchors.json` corrupt (running) | Keep last good in-memory list, log loudly. |
| `anchors.json` corrupt (cold start) | Start with empty list + prominent warning. Failure direction is always *less* trust. |
| Event with `Vouch` for an un-anchored identity | Treated as stranger (cert valid but you don't trust that Person). |
| Forged / invalid cert signature | Stranger; logged. |
| `Vouch.PeerID` ≠ verified publisher | Stranger; logged (cert replay by another node). |
| Expired cert (`ValidUntil` passed) | Stranger; `trust list` shows nothing (cache entry drops). |
| Expired anchor (`valid_until` passed) | Person resolves as stranger; `trust list` shows `EXPIRED`. |
| Person removed (`trust remove`) | All their vouched events score as stranger immediately (Invariant 6). Past score contributions are not clawed back — they fade via decay (lingering up to ~half-life; documented, §4.3 is the real fix). |
| Old node receives `Vouch` field | Ignored (additive field); it scores the event as a stranger. Graceful. |
| New node receives Event without `Vouch` | Stranger path. |
| `identity.key` / `person.key` too permissive | swarmd / swarmctl refuse to use it. |
| `person.key` absent | Node cannot be vouched; publishes Events with `Vouch=nil`. Fine. |

## Testing

TDD throughout. This touches reputation **and** trust, so the adversarial suite (CI
gate) gains scenarios in `test/adversarial/`:

- `TestSybilStrangerFloodCapped` — 100 strangers: total score ≤ cap, corroboration +1.
- `TestAnchoredPersonCountsOnce` — 3 machines, one cert chain, Person `jo` = 1 vote, full weight.
- `TestSpoofedReporterDropped` — `ReporterID` ≠ verified publisher never reaches the engine.
- `TestVouchForgedSignatureIsStranger` — bad `Sig` → stranger.
- `TestVouchPeerIDMismatchIsStranger` — cert replayed by another node → stranger.
- `TestVouchUnanchoredIdentityIsStranger` — valid cert, un-anchored Person → stranger.
- `TestExpiredVouchIsStranger` and `TestExpiredAnchorIsStranger`.
- `TestPersonRemovalAppliesImmediately` — Invariant 6.

Unit tests: node identity persist/reload yields same peer ID; person-key cert
issue/verify round-trip; anchor store load / hot-reload / corrupt-file / atomic
visibility; cert cache verification; engine group math and stranger cap. Integration:
pipeline test with one vouched and one stranger reporter end to end, including the
on-wire `Vouch` round-trip.

Wire-protocol skill checklist (per CLAUDE.md): bump `SchemaVersion`, confirm the new
field is additive and back-compatible, add a round-trip encode/decode test for
`PeerCert` and `Event{Vouch}`.

## Documentation (same PR)

- `docs/onboarding/03-key-management.md`: node key vs person key, file locations,
  permissions, backup, fingerprint verification ritual, cert issuance/rotation.
- `docs/federation-guide.md`: new "Pairing with a friend" section — `identity init` →
  `identity show` → exchange + verify fingerprint → `trust add --identity` → certs flow
  on the wire.
- `CHANGELOG.md` entry incl. the `SchemaVersion` 0 → 1 bump.

## Invariant check

1. **Lists are aids, not law** — every weight and cap is config-overridable. ✅
2. **IPs cleartext / no pseudo-hashing** — untouched. ✅
3. **Local-only whitelist never federated** — untouched; Person↔peer bindings are local trust, not shared. ✅
4. **O(1) enforcement** — untouched. ✅
5. **Trust rises slowly, falls fast** — static anchors don't auto-rise; removal is immediate for future reports; decay lingering of past contributions documented. Full asymmetry arrives with §4.3. ✅ (with noted limitation)
6. **Anchors locally removable** — `trust remove`, immediate effect; only `self-added` anchors exist here. ✅
7. **`internal/enforce` / `scripts/install` security-critical** — neither is touched. ✅
8. **Wire contract** — additive field + `SchemaVersion` bump; implementation follows `.claude/skills/wire-protocol`. ✅
