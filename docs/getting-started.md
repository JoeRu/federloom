# Getting Started with FederLoom

FederLoom is a federated IP reputation system. This guide covers three paths:
**A** — solo node, **B** — start a new federation, **C** — join an existing federation.

Run `make build` first to produce `bin/federloomd` and `bin/federloomctl`.

---

## Option A — Solo node (single operator, no federation)

1. Start federloomd once to generate the node key:
   ```bash
   ./bin/federloomd -config config.yaml
   # (Ctrl-C after it prints "peer ID: 12D3Koo...")
   ```
2. Initialise your identity:
   ```bash
   ./bin/federloomctl setup --label "MyNode" -config config.yaml
   ```
3. Set `federation_mode: solo` in `config.yaml` and restart federloomd.
4. Done. Your node scores IP reputation locally.

---

## Option B — Start a new federation (first operator)

You are creating the federation that others will join.

1. Start federloomd once to generate the node key, then Ctrl-C.
2. Initialise your identity:
   ```bash
   ./bin/federloomctl setup --label "Alice" -config config.yaml
   ```
3. Generate an invitation for each operator who will join:
   ```bash
   ./bin/federloomctl federation invite \
       --addr /ip4/YOUR_PUBLIC_IP/tcp/7700 \
       --out alice.invite \
       -config config.yaml
   ```
   Send `alice.invite` to each joining operator over Signal, encrypted email, or any channel you already trust.
4. Ask them to read back the **fingerprint** shown during `federloomctl setup`. Verify it matches before they proceed.
5. For each reply bundle you receive:
   ```bash
   ./bin/federloomctl trust import bob.bundle --as bob --weight 0.8 -config config.yaml
   ```
6. Set `federation_mode: federated` in `config.yaml` and restart federloomd.

---

## Option C — Join an existing federation

You received an `alice.invite` file from an existing federation operator.

1. Start federloomd once to generate the node key, then Ctrl-C.
2. Initialise your identity:
   ```bash
   ./bin/federloomctl setup --label "Bob" -config config.yaml
   ```
3. Join using the invitation:
   ```bash
   ./bin/federloomctl federation join alice.invite -config config.yaml
   ```
   You will be shown a fingerprint. **Verify it with Alice** over a channel you already trust before typing `yes`.
4. Paste the printed config snippet into `config.yaml`:
   ```yaml
   federation_mode: federated
   bootstrap_peers:
     - /ip4/ALICE_IP/tcp/7700/p2p/12D3KooW...
   ```
5. Export your own bundle and send it back to Alice:
   ```bash
   ./bin/federloomctl trust export -config config.yaml > bob.bundle
   # send bob.bundle to Alice
   # Alice runs: federloomctl trust import bob.bundle --as bob --weight 0.8
   ```
6. Restart federloomd.

---

## Checking status at any time

```bash
./bin/federloomctl status -config config.yaml
```

Shows your node identity, person fingerprint, trust anchors, and bootstrap peers.

---

## Key management reference

| File | Purpose | Command |
|---|---|---|
| `data/reputation/identity.key` | libp2p node key (created by federloomd) | auto |
| `data/reputation/person.key` | operator Ed25519 key | `federloomctl setup` |
| `data/reputation/peer.cert` | node-to-operator binding | `federloomctl setup` |
| `data/reputation/anchors.json` | trusted operators | `federloomctl trust add/import` |
| `data/reputation/imported-certs.json` | peer certs from anchored operators | `federloomctl trust import` |

All paths are configurable via `trust.*_file` in `config.yaml`. See `docs/onboarding/03-key-management.md` for the full reference.

---

## Troubleshooting

**Scores not syncing after setup**
Restart federloomd — it reads identity files on startup, not live.

**Fingerprint mismatch during join**
Stop immediately. Do not type `yes`. Contact the inviting operator on a separate channel to verify identity.

**`no person identity` error**
Run `federloomctl setup --label NAME` first.

**`node key not found` error**
Start federloomd at least once before running `federloomctl setup`. Swarmd generates the node key (`identity.key`) on first boot.

**Peer cert expired**
Re-run `federloomctl setup` — it will reissue the cert. Or use `federloomctl peer-cert <PEER_ID>` to issue a new one manually.

**Weight set to 0**
A weight of 0 means events from that operator are silently ignored. Use `federloomctl trust set --weight 0.8 PERSON` to fix it.

**Bootstrap peer not connecting**
Check that port 7700/tcp is open in your firewall and that the peer ID in `bootstrap_peers` matches the ID printed by federloomd (`peer ID: 12D3Koo...` in the startup log).

---

## Integration guides

Once your node is running, connect it to your existing tools:

- **[DNSBL integration](dnsbl-integration.md)** — wire Postfix, Rspamd, nginx, and fail2ban against FederLoom's embedded DNSBL server
