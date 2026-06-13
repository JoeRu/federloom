# Onboarding 3/4 — Key management

*Founding duty of every federation (spec §6.3).*

SwarmGuard uses three types of keys per node. Understanding them upfront prevents
hard-to-reverse mistakes later.

---

## The three keys

| Key | File | Purpose | Created by |
|-----|------|---------|-----------|
| **Node (libp2p) key** | `<store.dir>/identity.key` | Peer ID on the gossipsub wire | `swarmd` on first start |
| **Person identity key** | `<store.dir>/person.key` | Binds a human to their machines (Ed25519) | `swarmctl identity init` |
| **Peer cert** | `<store.dir>/peer.cert` | Vouches that this node is operated by you | `swarmctl identity init` (self-cert) or `swarmctl peer-cert` |

The Person key is optional for solo mode. It becomes important as soon as you
want other operators to trust your reports specifically (spec §5.1).

---

## Setting up a Person identity

Run once per operator (not once per machine):

```bash
# Create the Person key and self-certify this machine in one step.
swarmctl identity init --label "Alice"

# Output:
# person identity created: data/reputation/person.key
# public key:  ed25519:AAAA...
# fingerprint: ab12 cd34 ef56 78gh
# self peer-cert installed: data/reputation/peer.cert
```

The fingerprint is what you share with others out-of-band so they can verify
your key before anchoring it.

```bash
# Inspect the identity you just created.
swarmctl identity show

# Print this node's libp2p peer ID (needed when certifying additional machines).
swarmctl identity
```

---

## Certifying additional machines

Each machine you operate needs its own peer cert, signed by your Person key:

```bash
# On the new machine: get its peer ID after first swarmd start.
swarmctl identity   # prints 12D3KooW...

# On the machine with the Person key: sign a cert for the new peer.
swarmctl peer-cert 12D3KooWnewmachine --valid-for 8760h > new-machine.cert.json

# Transfer new-machine.cert.json to the new machine and install it.
# Place the JSON content at <store.dir>/peer.cert on the new machine.
```

---

## Anchoring a trusted peer

To trust another operator's reports, anchor their Person identity. You need
their public key (from `swarmctl identity show` on their side):

```bash
# Manual anchor — paste their public key directly.
swarmctl trust add --identity ed25519:BBBB... --weight 0.8 alice

# Or import their full bundle (key + all their machine certs) from a file.
swarmctl trust import alice.bundle --as alice --weight 0.8

# List all anchored persons.
swarmctl trust list

# Adjust weight for an existing anchor.
swarmctl trust set alice --weight 0.6

# Remove an anchor — takes effect within the trust reload interval (≤10s).
swarmctl trust remove alice
```

### Weight guidelines

| Weight | Meaning |
|--------|---------|
| 0.9    | High confidence (same organisation, physically verified key) |
| 0.7    | Trusted acquaintance (key fingerprint verified via voice/video) |
| 0.5    | Known community member (fingerprint shared in signed email) |
| 0.3    | Default stranger weight (config `trust.stranger_weight`) |

---

## Exporting your bundle for others to import

```bash
# Print your Person identity and all your machine certs as a JSON bundle.
swarmctl trust export > alice.bundle
```

Share `alice.bundle` over a channel you already trust (Signal, encrypted email,
in-person). The recipient verifies the fingerprint before importing.

---

## Key management policy (define these up front)

- **Issuance & vouching** — who issues the Person key, who may certify new
  machines (only you, via `swarmctl peer-cert`).
- **Validity periods** — default cert validity is 1 year (`--valid-for 8760h`);
  shorter is safer for machines you operate less frequently.
- **Rotation** — generate a new Person key with `swarmctl identity init` on a
  spare machine and re-certify all nodes; re-share your bundle with peers who
  have anchored you.
- **Revocation** — there is no central CRL; to revoke, ask peers to
  `swarmctl trust remove <you>` and re-import after rotation. Short cert
  validity reduces blast radius — expired certs resolve as strangers automatically.
- **Compromise** — fast-revoke: ask all peers to `swarmctl trust remove <you>`;
  asymmetric decay (trust rises slowly, falls fast — spec §4.3) limits damage
  from a short window of malicious reports.

Keys and filled-in secrets are never committed (see `.gitignore`).
