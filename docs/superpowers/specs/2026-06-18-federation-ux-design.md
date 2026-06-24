# Federation UX Design

**Feature:** Federation setup wizard, invitation protocol, and status command
**Date:** 2026-06-18
**Status:** Approved

## Problem

Setting up a FederLoom federation currently requires ~8 manual steps spread across CLI commands, config edits, and out-of-band key exchange with no guidance on ordering or what comes next. A new operator can easily miss the fingerprint verification step, end up with uncertified anchors, or not know what to paste into config.yaml. There is no single entry point that says "start here."

## Goal

Add three new `federloomctl` subcommands and one new doc that together reduce federation setup to a guided, linear flow:

1. `federloomctl setup` — initialises node identity and person identity on any new machine
2. `federloomctl federation invite` — generates a shareable invitation bundle for new operators
3. `federloomctl federation join` — consumes an invitation, imports trust, and prints the config snippet
4. `federloomctl status` — shows current local identity, anchor, and bootstrap-peer state at a glance
5. `docs/getting-started.md` — single entry-point guide covering solo, start-a-federation, and join-a-federation flows

No config files are written automatically. All commands print what to paste; the operator decides when to apply it.

---

## Data Model: Invitation Bundle

New type in `internal/federation/invitation.go`:

```go
package federation

// Invitation is the shareable bundle an existing federation member generates
// and sends to an operator who wants to join.
type Invitation struct {
    Version    int          `json:"version"`     // always 1
    CreatedAt  time.Time    `json:"created_at"`
    InvitedBy  string       `json:"invited_by"`  // person label of the inviter
    Federation FedInfo      `json:"federation"`
    Trust      trust.Bundle `json:"trust_bundle"`
}

type FedInfo struct {
    Mode          string `json:"mode"`           // "federated" | "isolated"
    BootstrapPeer string `json:"bootstrap_peer"` // single multiaddr: /ip4/.../tcp/7700/p2p/12D3...
}

func NewInvitation(cfg *config.Config, label string, transportAddr string) (*Invitation, error)
func WriteInvitation(w io.Writer, inv *Invitation) error
func ReadInvitation(r io.Reader) (*Invitation, error)
```

`NewInvitation` loads the person key from `cfg.TrustPersonKeyFile()`, loads all issued certs from `issuedCertsPath`, and assembles the bundle. `transportAddr` is the transport-only multiaddr (e.g. `/ip4/1.2.3.4/tcp/7700`) — `NewInvitation` reads the node key from `cfg.NodeKeyFile()` to derive the peer ID and constructs the full `/ip4/.../tcp/.../p2p/12D3...` multiaddr stored in `federation.bootstrap_peer`. The operator never needs to type their peer ID manually.

`trust.Bundle` is the existing type from `internal/trust/bundle.go` — no new wire format.

The invitation file is human-readable JSON. Operators share it over Signal, encrypted email, or any channel they already trust. The fingerprint inside is verified out-of-band before the joining operator presses Enter.

---

## `federloomctl setup`

**File:** `cmd/federloomctl/setup.go`

**Usage:** `federloomctl setup [--label NAME] [-config PATH]`

A "doctor" command — checks what exists, creates what is missing, prints a summary. Idempotent: safe to run multiple times.

### Flow

```
[1/3] Node key
      peer ID: 12D3KooWAbc...            (already exists)
      — or —
      federloomd must run once first to generate the node key — then re-run setup.

[2/3] Person identity
      creating person.key...             (if missing)
      — or —
      public key:  ed25519:AAAA...       (already exists)
      fingerprint: ab12 cd34 ef56 78gh

[3/3] Peer certificate
      self-certifying this node...       (if missing)
      installed: data/reputation/peer.cert  (valid 365d)
      — or —
      peer.cert valid until 2027-06-18  (364d remaining)

Setup complete.

Share your fingerprint (ab12 cd34 ef56 78gh) with operators you want to federate with.
Next: federloomctl federation invite --addr /ip4/YOUR_IP/tcp/7700 > invite.json
```

### Rules

- `--label NAME` sets the person label. If omitted and no person key exists, prompt interactively: `Enter your name (label for this identity): `.
- If the node key is missing (federloomd hasn't run yet), print the warning and exit 1 — setup cannot continue without a peer ID.
- If everything already exists, print the current state and exit 0.
- Does not modify `config.yaml`.

---

## `federloomctl federation invite`

**File:** `cmd/federloomctl/federation.go`

**Usage:** `federloomctl federation invite --addr TRANSPORT_ADDR [--weight W] [--out FILE] [-config PATH]`

`--addr` is required: the inviting node's public transport multiaddr WITHOUT the peer ID component (e.g. `/ip4/1.2.3.4/tcp/7700`). `NewInvitation` reads the local node key to append the peer ID automatically, producing the complete `bootstrap_peer` entry in the invitation. Validated with `multiaddr.NewMultiaddr`.

Generates the invitation bundle and writes it to stdout (default) or `--out FILE`.

```
$ federloomctl federation invite --addr /ip4/1.2.3.4/tcp/7700/p2p/12D3... --out alice.invite

invitation written to alice.invite
→ send alice.invite to the operator joining your federation
→ ask them to verify fingerprint: ab12 cd34 ef56 78gh
```

Fails with a clear error if the person identity does not exist: "no person identity — run `federloomctl setup` first".

Default `--weight` for the invitation is the config `trust.anchor_weight` (same default as `trust add`). The weight is informational in the invitation — the joining operator can override it with `federloomctl federation join --weight`.

---

## `federloomctl federation join`

**Usage:** `federloomctl federation join FILE [--as NAME] [--weight W] [-config PATH]`

On the joining node. Reads the invitation file, guides through verification, imports the trust bundle, and prints the config snippet plus the reciprocal export command.

```
$ federloomctl federation join alice.invite

Invitation from: alice
Bootstrap peer:  /ip4/1.2.3.4/tcp/7700/p2p/12D3KooW...
Federation mode: federated

Fingerprint: ab12 cd34 ef56 78gh
Verify this with alice over a channel you already trust, then type 'yes' to continue: yes

✓ anchored alice (weight 0.80)
✓ imported 2 cert(s)

Add to your config.yaml:
──────────────────────────────────────────
  federation_mode: federated
  bootstrap_peers:
    - /ip4/1.2.3.4/tcp/7700/p2p/12D3KooW...
──────────────────────────────────────────

Now send alice your bundle so she can anchor you back:
  federloomctl trust export > my.bundle
  # send my.bundle to alice
  # alice runs: federloomctl trust import my.bundle --as bob --weight 0.8
```

### Rules

- If the user types anything other than `yes` at the verification prompt, abort without importing: "aborted — import nothing."
- `--as NAME` overrides the person label from the invitation (default: `invitation.InvitedBy`).
- `--weight W` overrides the trust weight (default: invitation weight, fallback to `cfg.Trust.AnchorWeight`).
- The import logic is identical to `federloomctl trust import`: verify certs, upsert anchor, merge into local cert cache. No new trust code.
- Does not write to `config.yaml`. The config snippet is printed, not applied.

---

## `federloomctl status`

**File:** `cmd/federloomctl/status.go`

**Usage:** `federloomctl status [-config PATH]`

Shows the current local state. No daemon connection required — reads from files only.

```
$ federloomctl status

NODE
  peer ID:     12D3KooWAbc...
  node key:    data/reputation/identity.key  ✓

IDENTITY
  person:      alice
  fingerprint: ab12 cd34 ef56 78gh
  peer cert:   valid until 2027-06-18  (364d remaining)

TRUST ANCHORS  (2)
  PERSON   WEIGHT  STATUS     FINGERPRINT          LABEL
  alice     1.00   ok         ab12 cd34 ef56 78gh  self
  bob       0.80   ok         cd34 ef56 78gh ab12  Bob's homelab

BOOTSTRAP PEERS  (1)
  /ip4/1.2.3.4/tcp/7700/p2p/12D3KooW...

  For live peer count: GET /api/v1/blocklist or check node logs.
```

### Rules

- The "self" row (alice at weight 1.00) is **synthesized** from the local person key — it is not read from the anchors file. `federloomctl status` reads `cfg.TrustPersonKeyFile()`, derives the fingerprint, and prepends this synthetic row so operators can always see and copy their own fingerprint. If no person key exists, the self row is omitted.
- STATUS column reuses the same `anchorStatus` logic already in `trust list` (`ok`, `certs-exp`, `no-certs`, `EXPIRED`).
- Bootstrap peers are read from `config.yaml`'s `bootstrap_peers` field.
- If a section has nothing configured, print: `not configured — run federloomctl setup`.
- Does not connect to the federloomd HTTP API. A hint at the bottom points to the API for live peer counts.

---

## `cmd/federloomctl/main.go` changes

Add three entries to the `usage()` function and `switch` dispatch:

```
federloomctl setup [--label NAME]
federloomctl status
federloomctl federation invite --addr MULTIADDR [--weight W] [--out FILE]
federloomctl federation join FILE [--as NAME] [--weight W]
```

`federation` dispatches to `cmdFederation(args)` in `federation.go`, which switches on `args[0]` (`invite` | `join`).

---

## Documentation

### `docs/getting-started.md` (new)

Single entry-point guide. Three paths:

**Option A — Solo node**
1. Build and start federloomd
2. `federloomctl setup --label "MyNode"`
3. Set `federation_mode: solo` in config, start federloomd
4. Done

**Option B — Start a federation (first operator)**
1. `federloomctl setup --label "Alice"`
2. `federloomctl federation invite --addr /ip4/YOUR_IP/tcp/7700 --out alice.invite`
3. Send `alice.invite` to each operator joining
4. For each reply bundle: `federloomctl trust import bob.bundle --as bob --weight 0.8`
5. Restart federloomd

**Option C — Join an existing federation**
1. `federloomctl setup --label "Bob"`
2. Receive `alice.invite` from the federation operator
3. `federloomctl federation join alice.invite`
4. Paste the printed config snippet into `config.yaml`
5. `federloomctl trust export > bob.bundle` → send to alice
6. Restart federloomd

Plus a **Key management reference** section (condenses `docs/onboarding/03-key-management.md`) and a **Troubleshooting** section covering common mistakes: forgetting to restart federloomd after config edit, skipping fingerprint verification, weight set to 0, peer cert expired.

### `docs/federation-guide.md` (modify)

Add at top:

```markdown
> For the quickest path, see [`docs/getting-started.md`](getting-started.md).
> This file covers the underlying concepts and advanced federation options.
```

### `README.md` (modify)

Replace the "Quick start (scaffold)" section with an "Install & first run" section that:
- Points to `docs/getting-started.md` as the primary entry point
- Shows the three-line solo setup: `make build` → `federloomctl setup` → start federloomd
- Replaces the "(currently stubs)" status note with current actual capabilities
- Updates the "Operating a federation?" section to mention `federloomctl setup` and `federloomctl federation invite/join` as the starting point, before the onboarding docs deep-dives

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `internal/federation/invitation.go` | Create | `Invitation` type, `NewInvitation`, `WriteInvitation`, `ReadInvitation` |
| `cmd/federloomctl/setup.go` | Create | `federloomctl setup` wizard |
| `cmd/federloomctl/federation.go` | Create | `federloomctl federation invite/join` |
| `cmd/federloomctl/status.go` | Create | `federloomctl status` |
| `cmd/federloomctl/main.go` | Modify | Add new subcommands to usage + dispatch |
| `docs/getting-started.md` | Create | Linear operator guide (solo / start / join) |
| `docs/federation-guide.md` | Modify | Add 2-line preamble pointing to getting-started |
| `README.md` | Modify | Update quickstart + federation section |

## Out of Scope

- Writing to `config.yaml` automatically (operators paste config snippets)
- Live peer count in `federloomctl status` (requires daemon API endpoint not yet designed)
- `federloomctl federation defederate` (exists in federation-guide.md conceptually; not a new command yet)
- IPv6 bootstrap peer addresses in the invitation (existing `bootstrap_peers` supports them; invitation carries one peer only)
- TUI / curses-based wizard (plain stdout is sufficient)
