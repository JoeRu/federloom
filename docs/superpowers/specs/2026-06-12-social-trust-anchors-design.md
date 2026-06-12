# Social Trust Anchors Design

**Date:** 2026-06-12
**Status:** Approved
**Spec references:** §5.1 (Trust-Anchor-Liste), §4.2 (Diversitäts-gewichtete Korroboration), §7.3 (AnchorEntry), Invariants 1 & 6

## Goal

Implement the first real trust layer: operators explicitly anchor peers they know
("I trust Jo, here is his server's peer ID"), anchored reporters drive
corroboration, and un-anchored strangers are capped so Sybil floods cannot push
an IP past the block threshold. This replaces the hardcoded `1.0` / `0.3` trust
constants in `internal/node/node.go` with a resolvable, operator-curated model.

**The human factor is the diversity dimension:** each human-vetted anchor *group*
is one independent corroboration vote. This implements §4.2's "Trust-Herkunft"
diversity without GeoIP/ASN data.

## Out of scope

- Dynamic node trust (§4.3 — trust rising/falling with behaviour). Anchors are
  static human grants; you remove a friend by removing them.
- Vouching / transitive trust ("anchor vouches for someone", §5.1).
- Dispute / whitelist votes (§4.4).
- Wire-format changes. `pkg/proto` is untouched; `Event.Signature` stays
  reserved for future relayed/federated events. Transport-layer authenticity
  comes from gossipsub message signing, which libp2p enables by default.
- Project-default anchors (`source: "project-default"`). Only `self-added` here.

## Architecture

Five components, all control plane. `internal/enforce` is not touched.

### 1. `internal/identity` — persistent node key

- Load-or-create an Ed25519 keypair at `<store.dir>/identity.key`, file mode
  0600. The libp2p host is built from this key, so the node's peer ID is stable
  across restarts — the prerequisite for being trusted.
- swarmd refuses to start if `identity.key` is group- or world-readable (same
  posture as SSH private keys).
- `swarmctl identity` prints the node's own peer ID for sharing with friends.

### 2. `internal/trust` — anchor store

- Reads `<store.dir>/anchors.json` (path overridable via `trust.anchors_file`).
- JSON schema: array of a local wrapper struct embedding `proto.AnchorEntry`
  plus one local-only field:

```json
[
  {
    "key_id": "12D3KooW...",
    "label": "Jo mailserver",
    "weight": 0.9,
    "valid_until": "0001-01-01T00:00:00Z",
    "source": "self-added",
    "group": "jo"
  }
]
```

- `group` is local-only and never leaves the node (it lives in
  `internal/trust`, not `pkg/proto`). An entry without a group uses its own
  `key_id` as its group.
- Hot reload: the store re-checks the file's mtime at most every 10 seconds and
  reloads on change. No daemon restart needed to add or remove a friend.
- Single public query:

```go
// Resolve returns the trust weight, the corroboration group, and whether
// peerID is an anchored (non-expired) reporter.
func (s *Store) Resolve(peerID string) (weight float64, group string, anchored bool)
```

- Anchored, non-expired → entry weight (default `trust.anchor_weight` = 0.9).
- Unknown or expired → `trust.stranger_weight` (default 0.3), group `""`,
  anchored = false.

### 3. `swarmctl trust` — pairing CLI

Manual peer-ID exchange over any channel the operators already trust (Signal,
phone, in person). Commands edit `anchors.json` directly via temp-file +
atomic rename; they work whether swarmd is running or not.

```
swarmctl identity                                  # print own peer ID
swarmctl trust add <peer-id> --label "Jo mailserver" [--weight 0.9] [--group jo]
swarmctl trust list                                # table incl. EXPIRED flag
swarmctl trust remove <peer-id>
```

- `add` prints the fingerprint (the peer ID, grouped for readability) back for
  verbal confirmation.
- `add` on an existing peer ID updates the entry in place (idempotent).
- Adding the node's own peer ID warns and is a no-op (local events already run
  at trust 1.0).
- swarmctl locates the data dir by reading the same `config.yaml` as swarmd
  (`--config` flag, same default path).

### 4. Verified sender binding — `internal/transport` + `internal/node`

- gossipsub signs every published message and verifies the publisher's identity
  on receipt. The subscription handler surfaces this verified publisher peer ID
  alongside the decoded `proto.Event`.
- The node **drops any event whose `ReporterID` does not equal the verified
  publisher** and logs the mismatch. This closes reporter spoofing with zero
  custom cryptography.
- Consequence: in this MVP a node may only report its own observations on
  gossip (no third-party relaying). `OriginTrace` stays unused until federation
  work.

### 5. Capped-stranger corroboration — `internal/reputation`

`Record` gains group/anchored awareness:

```go
func (e *Engine) Record(ip, reason, reporterID string, trust float64, group string, anchored bool) (float64, error)
```

`store.ScoreRecord` (BadgerDB value — local storage, not wire format) gains:

- `Groups []string` — distinct anchored groups that reported this IP.
- `StrangerContrib float64` — cumulative score points contributed by strangers.

Scoring rules:

- **Anchored reporter:** full logistic contribution as today
  (`trust × weightFor(reason) × (1 − score/100)`). Its group is added to
  `Groups` if new.
- **Stranger:** same formula, but the contribution is clamped so
  `StrangerContrib` never exceeds `trust.stranger_score_cap` (default 15).
  Once at the cap, further stranger reports still update `LastSeen` /
  `Reasons` / `ReporterIDs` but add zero score.
- **Corroboration** = `len(Groups)` + 1 if any stranger has reported, else 0.
  Three machines in group `jo` are one vote; one hundred Sybil strangers are
  one vote and at most 15 points — forever.
- **Local ingest events are unchanged:** trust 1.0, own peer ID, the node is
  implicitly its own anchored group.
- Decay, TTL, thresholds, and enforcement are untouched.

Worked example (block threshold 50, `ssh-auth-bruteforce` weight 10): Jo's three
servers (group `jo`, weight 0.9) plus 100 Sybils all report one IP. Sybils
contribute ≤ 15 points total. Jo's servers contribute ~9 points per report but
count as one corroboration group. The IP crosses the threshold only when a
second group — another human, or the operator's own honeypot — corroborates.
One compromised friend cannot cross the threshold alone; neither can any number
of Sybils.

## Config additions (`internal/config`)

```yaml
trust:
  anchors_file: ""          # default <store.dir>/anchors.json
  anchor_weight: 0.9        # default for entries without explicit weight
  stranger_weight: 0.3      # replaces the hardcoded 0.3 in node.go
  stranger_score_cap: 15    # max total score points strangers add per IP
```

All values operator-overridable (Invariant 1). Existing hardcoded constants in
`node.go:136/157` are replaced by `trust.Resolve` results.

## Edge cases & failure behaviour

| Case | Behaviour |
|---|---|
| `anchors.json` missing | Empty anchor list; everyone is a stranger. Normal cold start, not an error. |
| `anchors.json` corrupt (running) | Keep last good in-memory list, log loudly. |
| `anchors.json` corrupt (cold start) | Start with empty list + prominent warning. Failure direction is always *less* trust. |
| Concurrent write/read | swarmctl writes temp file + atomic rename; swarmd only ever reads a complete file. |
| `valid_until` passed | Entry resolves as stranger; `trust list` shows `EXPIRED`. Default on add: zero time = no expiry. |
| Anchor removed | Future reports score as stranger immediately. Past contributions are not clawed back — they fade via decay (up to ~half-life lingering; documented limitation, §4.3 dynamic trust is the real fix). |
| Weight out of range | `trust add` rejects weight outside (0, 1]. |
| `identity.key` too permissive | swarmd refuses to start. |

## Testing

TDD throughout. This touches reputation **and** trust, so the adversarial suite
(CI gate) gets new scenarios in `test/adversarial/`:

- `TestSybilStrangerFloodCapped` — 100 stranger reporters: total score ≤ cap,
  corroboration contribution is exactly 1.
- `TestAnchoredGroupCountsOnce` — 3 peer IDs in group `jo` = 1 corroboration
  vote, full score weight.
- `TestSpoofedReporterDropped` — event with `ReporterID` ≠ verified publisher
  never reaches the engine.
- `TestAnchorRemovalAppliesImmediately` — Invariant 6: after removal, the next
  report from that peer scores as stranger.
- `TestExpiredAnchorTreatedAsStranger`.

Unit tests: identity persist/reload yields the same peer ID; trust store
load / hot-reload / corrupt-file behaviour / atomic visibility; engine group
math and stranger cap. Integration: pipeline test with one anchored and one
stranger reporter end to end.

## Documentation (same PR)

- `docs/onboarding/03-key-management.md`: identity file location, permissions,
  backup, fingerprint verification ritual.
- `docs/federation-guide.md`: new "Pairing with a friend" section
  (`swarmctl identity` → exchange → `trust add` → verbal fingerprint check).
- `CHANGELOG.md` entry.

## Invariant check

1. **Lists are aids, not law** — every weight and cap is config-overridable. ✅
2. **IPs cleartext / no pseudo-hashing** — untouched. ✅
3. **Local-only whitelist never federated** — untouched; `group` is likewise local-only. ✅
4. **O(1) enforcement** — untouched. ✅
5. **Trust rises slowly, falls fast** — static anchors don't auto-rise; removal is immediate for future reports. Decay lingering of past contributions documented; full asymmetry arrives with §4.3. ✅ (with noted limitation)
6. **Anchors locally removable** — `trust remove`, immediate effect, only `self-added` anchors exist in this MVP. ✅
7. **`internal/enforce` / `scripts/install` security-critical** — neither is touched. ✅
