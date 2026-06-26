# Getting Started (Docker) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `docs/getting-started.md` with a Docker-first guide covering Mailcow, WordPress, CrowdSec standalone, and fail2ban integrations, targeted at generic self-hosters with zero prior FederLoom knowledge.

**Architecture:** Single file rewrite. All new content follows the "pick your stack → one section" pattern from the design spec. Existing binary/federloomctl content moves to a clearly-marked appendix at the bottom — not deleted.

**Tech Stack:** Markdown only. No code changes.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-26-getting-started-docker-design.md`
- File to rewrite: `docs/getting-started.md` (same path, preserve git history — do NOT delete and recreate)
- Exact metric names (verified in `internal/observability/prometheus.go`):
  - `federloom_blocked_ips` — gauge (not `_total`)
  - `federloom_events_received_total` — counter
  - `federloom_federation_peers` — gauge
- All cross-reference links must resolve to existing files:
  - `federation-guide.md` ✓ exists
  - `dnsbl-integration.md` ✓ exists
- Bootstrap scripts referenced are at:
  - `deploy/honeypot/bootstrap.sh`
  - `deploy/mailcow/bootstrap-mailcow.sh`
  - `deploy/wordpress/bootstrap-wordpress.sh`
- `.env.example` files are at:
  - `deploy/honeypot/.env.example`
  - `deploy/mailcow/.env.example`
  - `deploy/wordpress/.env.example`
- No new files, no bootstrap script changes, no docker-compose changes

---

### Task 1: Rewrite docs/getting-started.md

**Files:**
- Modify: `docs/getting-started.md` (full rewrite — overwrite entire contents)

**Interfaces:**
- Consumes: `docs/superpowers/specs/2026-06-26-getting-started-docker-design.md` (requirements)
- Consumes: current `docs/getting-started.md` (binary/federloomctl content to preserve as appendix)
- Produces: the finished guide — no other tasks depend on this

---

- [ ] **Step 1: Read the spec and the current file**

Read both files before writing anything:
```
docs/superpowers/specs/2026-06-26-getting-started-docker-design.md
docs/getting-started.md   (extract the binary/federloomctl content for the appendix)
```

Content to extract from the current file for the appendix:
- Option A (solo node with binary), Option B (start federation), Option C (join federation)
- Key management reference table
- Troubleshooting section
- The final "Integration guides" link block (keep `dnsbl-integration.md` link)

---

- [ ] **Step 2: Write the new docs/getting-started.md**

Overwrite the file with exactly the following content. Do not paraphrase — use
these exact headings, table column names, command strings, and metric names.

````markdown
# Getting Started with FederLoom

FederLoom is a federated, trust-weighted IP blocklist you self-host as a
Docker container. It ingests threat signals from your existing tools —
Mailcow, CrowdSec, fail2ban, WordPress logs — scores IPs locally using a
configurable rules engine, and optionally shares reputation with peers you
trust: peer-to-peer, no central authority. This guide covers the Docker
path; no build tools required. At the end you will have a running container
blocking IPs and exposing Prometheus metrics at `:9101/metrics`.

---

## Prerequisites

- Docker Engine ≥ 24 and Compose v2 (`docker compose`, not `docker-compose`)
- `rsync` installed locally (used by bootstrap scripts to sync the repo to
  the remote server)
- SSH access to the target server
- Port 7700/tcp open on the server if you want inbound federation peers
  (outbound-only peering works without opening the port)

No Go toolchain needed — the image is pulled from
`ghcr.io/joeru/federloom:latest`.

---

## Pick your stack

| My setup | Jump to |
|---|---|
| Mailcow mail server | [§ Mailcow](#mailcow) |
| WordPress / nginx / traefik + CrowdSec | [§ WordPress / generic web](#wordpress--generic-web) |
| Any server running CrowdSec (no Mailcow) | [§ CrowdSec standalone](#crowdsec-standalone) |
| Any server running fail2ban in Docker | [§ fail2ban](#fail2ban) |
| Just want to try it / standalone sensor | [§ Standalone node](#standalone-node) |

---

## Standalone node

**What you get:** A FederLoom node that runs a Cowrie SSH honeypot and
OpenCanary (SMTP/IMAP/HTTP), ingests their logs, scores IPs, and exposes
metrics. No integration with external tools required.

### 1. Configure `.env`

```bash
cp deploy/honeypot/.env.example deploy/honeypot/.env
```

Edit `deploy/honeypot/.env`:

| Variable | What it is | Example |
|---|---|---|
| `SERVER` | SSH hostname or IP of the server | `203.0.113.10` |
| `SSH_PORT` | SSH port | `22` |
| `SSH_USER` | SSH user | `root` |
| `REMOTE_DIR` | Deploy path on the server | `/opt/federloom` |
| `PUBLIC_IP` | Server's public IP (printed in multiaddr output) | `203.0.113.10` |
| `CTR` | FederLoom container name | `federloom` |
| `ADVERTISE_ADDR` | Public multiaddr for federation | `/ip4/203.0.113.10/tcp/7700` |
| `DNSBL_ZONE` | DNSBL zone suffix — trailing dot required | `dnsbl.example.com.` |
| `BOOTSTRAP_PEER` | Leave empty on first run | `` |
| `FEDERLOOM_API_TOKEN` | API bearer token | output of `openssl rand -hex 32` |

### 2. Run

```bash
bash deploy/honeypot/bootstrap.sh
```

The script installs Docker on the server if needed, syncs the repo, pulls
the image, and starts the stack. At the end it prints:

```
Honeypot stack running on 203.0.113.10
  Peer ID : 12D3KooW...
  Bootstrap multiaddr: /ip4/203.0.113.10/tcp/7700/p2p/12D3KooW...
```

Save the multiaddr — you will need it to connect other nodes.

### 3. Verify

```bash
curl -s http://YOUR_PUBLIC_IP:9101/metrics | grep federloom_blocked_ips
# Expected: federloom_blocked_ips 0   (0 is healthy on a fresh node)
```

---

## Mailcow

**What you get:** FederLoom runs as a sidecar alongside Mailcow. It reads
Postfix and Dovecot container logs for brute-force and spam signals, pulls
CrowdSec LAPI decisions, and blocks IPs via ipset on the host kernel. Port
7700 enables outbound (and optionally inbound) federation.

### 1. Create `/opt/federloom` on the server

The deploy directory must exist and be writable by your SSH user:

```bash
ssh -p SSH_PORT SSH_USER@SERVER \
  'sudo mkdir -p /opt/federloom && sudo chown $USER /opt/federloom'
```

### 2. Configure `.env`

```bash
cp deploy/mailcow/.env.example deploy/mailcow/.env
```

Edit `deploy/mailcow/.env`:

| Variable | What it is | How to find it |
|---|---|---|
| `SERVER` | SSH hostname | `mail.example.com` |
| `SSH_PORT` | SSH port | `2222` is typical for Mailcow servers |
| `SSH_USER` | SSH user (needs sudo + docker group) | — |
| `REMOTE_DIR` | Deploy path | `/opt/federloom` |
| `PUBLIC_IP` | Server's public IP | `dig +short mail.example.com` |
| `TAILSCALE_IP` | Tailscale IP for Prometheus scraping (optional) | `100.x.x.x` — omit if no Tailscale |
| `CROWDSEC_CTR` | CrowdSec container name | `docker ps \| grep crowdsec` on the server |
| `POSTFIX_CTR` | Postfix container name | `docker ps \| grep postfix` on the server |
| `DOVECOT_CTR` | Dovecot container name | `docker ps \| grep dovecot` on the server |
| `MAILCOW_NETWORK` | Mailcow Docker network CIDR (whitelisted) | `docker network inspect mailcowdockerized_mailcow-network \| grep Subnet` |
| `DOCKER_BRIDGE` | Docker bridge CIDR (whitelisted) | `172.17.0.0/16` default |
| `BOOTSTRAP_PEER` | Peer to connect to on startup | empty for solo; honeypot multiaddr to federate |

### 3. Run

```bash
bash deploy/mailcow/bootstrap-mailcow.sh
```

The script registers a CrowdSec bouncer, syncs the repo, pulls the image,
writes `config.local.yaml` with the bouncer API key, and starts the
container. At the end it prints the peer ID and multiaddr.

### 4. Verify

```bash
curl -s http://SERVER:9101/metrics | grep -E 'federloom_blocked_ips|federloom_federation_peers'
# federloom_blocked_ips 0         (0 is fine on a fresh node)
# federloom_federation_peers 0    (becomes 1+ once peered)
```

After the first CrowdSec poll (30 s):

```bash
curl -s http://SERVER:9101/metrics | grep federloom_events_received_total
# federloom_events_received_total{reason="...",...} N
```

---

## WordPress / generic web

**What you get:** FederLoom runs alongside your web stack. It reads CrowdSec
LAPI decisions (HTTP scanning, exploit attempts, bruteforce), blocks IPs via
ipset, and federates with peers. Also installs an effectiveness-exporter cron
that writes node_exporter textfile metrics.

### 1. Configure `.env`

```bash
cp deploy/wordpress/.env.example deploy/wordpress/.env
```

Edit `deploy/wordpress/.env`:

| Variable | What it is | How to find it |
|---|---|---|
| `SERVER` | SSH hostname | `d.example.com` |
| `SSH_PORT` | SSH port | `22` or `2222` |
| `SSH_USER` | SSH user | `root` or user with docker group |
| `REMOTE_DIR` | Deploy path | `/opt/federloom` |
| `PUBLIC_IP` | Server's public IP | `dig +short d.example.com` |
| `TAILSCALE_IP` | Tailscale IP for Prometheus (optional) | `100.x.x.x` |
| `CROWDSEC_CTR` | CrowdSec container name | `docker ps \| grep crowdsec` |
| `CROWDSEC_LAPI_IP` | CrowdSec LAPI IP inside the Docker network | `docker inspect crowdsec \| grep '"IPAddress"'` |
| `WP_NETWORK` | Web stack Docker network CIDR (whitelisted) | `docker network inspect <network> \| grep Subnet` |
| `DOCKER_BRIDGE` | Docker bridge CIDR (whitelisted) | `172.17.0.0/16` default |
| `BOOTSTRAP_PEER` | Peer to connect to on startup | empty for solo; honeypot multiaddr to federate |

### 2. Run

```bash
bash deploy/wordpress/bootstrap-wordpress.sh
```

The script registers a CrowdSec bouncer, syncs the repo, pulls the image,
writes `config.local.yaml`, starts the container, and installs the
effectiveness-exporter cron. At the end it prints the peer ID and multiaddr.

### 3. Verify

```bash
curl -s http://SERVER:9101/metrics | grep -E 'federloom_blocked_ips|federloom_federation_peers'
```

---

## CrowdSec standalone

**What you get:** FederLoom as a CrowdSec bouncer on any server running
CrowdSec — without Mailcow or a web stack. Pulls decisions from the local
LAPI and blocks IPs via ipset.

Follow the [§ WordPress / generic web](#wordpress--generic-web) steps with
these adjustments:

| Variable | Adjust to |
|---|---|
| `CROWDSEC_LAPI_IP` | `127.0.0.1` if CrowdSec runs on the host (not in a container) |
| `WP_NETWORK` | your server's main Docker network CIDR, or `172.17.0.0/16` if no custom networks |
| `CROWDSEC_CTR` | your CrowdSec container name (`docker ps \| grep crowdsec`) |

The bootstrap script and container image are the same as the WordPress path.

---

## fail2ban

**What you get:** FederLoom polls a fail2ban Docker container for banned IPs
via `docker exec <container> fail2ban-client banned`, maps jail names to
reason codes, and scores IPs accordingly.

**Supported jail → reason mappings:**

| fail2ban jail | FederLoom reason |
|---|---|
| `sshd`, `ssh`, `sshd-*` | `ssh-auth-bruteforce` |
| `postfix`, `postfix-sasl`, `postfix-*` | `smtp-auth-bruteforce` |
| `dovecot`, `dovecot-*` | `imap-auth-bruteforce` |
| `nginx-http-auth`, `nginx-*` | `http-auth-bruteforce` |
| `apache-auth`, `apache-*` | `http-auth-bruteforce` |
| `wordpress`, `wp-*` | `http-wp-bruteforce` |
| `recidive` | `recidive` |

### 1. Set up the node

There is no dedicated fail2ban bootstrap script. Use the
[§ Standalone node](#standalone-node) setup first to get a running node,
then enable the fail2ban ingest plugin.

### 2. Enable fail2ban ingest

SSH in to the server and append to the config:

```bash
ssh -p SSH_PORT SSH_USER@SERVER bash -s <<'EOF'
cat >> /opt/federloom/deploy/honeypot/config.yaml <<'YAML'
ingest:
  fail2ban:
    enabled: true
    container: fail2ban        # replace with your container name: docker ps | grep fail2ban
    poll_interval: 30s
YAML
docker restart federloom
EOF
```

Replace `fail2ban` with your actual container name if different.

### 3. Verify

```bash
# Wait 30 seconds for the first poll, then:
curl -s http://YOUR_PUBLIC_IP:9101/metrics | grep 'federloom_events_received_total.*bruteforce'
# Expected: one or more lines with count > 0 if fail2ban has active bans
```

---

## Federation (once running)

Once your node is healthy, connect it to peers:

**Outbound-only (no inbound port required):** set `BOOTSTRAP_PEER` in your
`.env` to another operator's multiaddr (printed at the end of their bootstrap
run) and re-run the bootstrap script:

```
BOOTSTRAP_PEER=/ip4/PEER_IP/tcp/7700/p2p/12D3KooW...
```

**Full mesh (inbound + outbound):** open port 7700/tcp in your firewall.
Share your multiaddr with peer operators — it is printed by every bootstrap
script:

```
Multiaddr: /ip4/YOUR_IP/tcp/7700/p2p/12D3KooW...
```

For trust setup, invitation exchange, and weight tuning see
[`docs/federation-guide.md`](federation-guide.md).

---

## Appendix: Binary / development path

The sections below cover running FederLoom from a compiled binary rather
than Docker. This is primarily useful for development and testing.

Run `make build` first to produce `bin/federloomd` and `bin/federloomctl`.

### Option A — Solo node (single operator, no federation)

1. Start federloomd once to generate the node key:
   ```bash
   ./bin/federloomd -config config.yaml
   # Ctrl-C after it prints "peer ID: 12D3Koo..."
   ```
2. Initialise your identity:
   ```bash
   ./bin/federloomctl setup --label "MyNode" -config config.yaml
   ```
3. Set `federation_mode: solo` in `config.yaml` and restart federloomd.

### Option B — Start a new federation (first operator)

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
   Send `alice.invite` over Signal, encrypted email, or any channel you
   already trust.
4. Ask each recipient to read back the **fingerprint** shown during
   `federloomctl setup`. Verify it matches before they proceed.
5. For each reply bundle you receive:
   ```bash
   ./bin/federloomctl trust import bob.bundle --as bob --weight 0.8 -config config.yaml
   ```
6. Set `federation_mode: federated` in `config.yaml` and restart federloomd.

### Option C — Join an existing federation

1. Start federloomd once to generate the node key, then Ctrl-C.
2. Initialise your identity:
   ```bash
   ./bin/federloomctl setup --label "Bob" -config config.yaml
   ```
3. Join using the invitation:
   ```bash
   ./bin/federloomctl federation join alice.invite -config config.yaml
   ```
   You will be shown a fingerprint. **Verify it with Alice** over a trusted
   channel before typing `yes`.
4. Paste the printed config snippet into `config.yaml`:
   ```yaml
   federation_mode: federated
   bootstrap_peers:
     - /ip4/ALICE_IP/tcp/7700/p2p/12D3KooW...
   ```
5. Export your own bundle and send it back to Alice:
   ```bash
   ./bin/federloomctl trust export -config config.yaml > bob.bundle
   ```
6. Restart federloomd.

### Key management reference

| File | Purpose | Command |
|---|---|---|
| `data/reputation/identity.key` | libp2p node key (created by federloomd) | auto |
| `data/reputation/person.key` | operator Ed25519 key | `federloomctl setup` |
| `data/reputation/peer.cert` | node-to-operator binding | `federloomctl setup` |
| `data/reputation/anchors.json` | trusted operators | `federloomctl trust add/import` |
| `data/reputation/imported-certs.json` | peer certs from anchored operators | `federloomctl trust import` |

All paths are configurable via `trust.*_file` in `config.yaml`. See
`docs/onboarding/03-key-management.md` for the full reference.

### Troubleshooting

**Scores not syncing after setup** — restart federloomd; it reads identity
files on startup, not live.

**Fingerprint mismatch during join** — stop immediately; do not type `yes`.
Contact the inviting operator on a separate channel to verify identity.

**`no person identity` error** — run `federloomctl setup --label NAME` first.

**`node key not found` error** — start federloomd at least once before
running `federloomctl setup`.

**Peer cert expired** — re-run `federloomctl setup` to reissue.

**Weight set to 0** — events from that operator are silently ignored. Fix
with `federloomctl trust set --weight 0.8 PERSON`.

**Bootstrap peer not connecting** — check that port 7700/tcp is open and
that the peer ID in `bootstrap_peers` matches the ID printed by federloomd.

---

## Integration guides

- **[DNSBL integration](dnsbl-integration.md)** — wire Postfix, Rspamd,
  nginx, and fail2ban against FederLoom's embedded DNSBL server
````

---

- [ ] **Step 3: Verify all cross-reference links exist**

```bash
ls docs/federation-guide.md docs/dnsbl-integration.md docs/onboarding/03-key-management.md
# Expected: all three paths print without error
```

- [ ] **Step 4: Verify metric names appear verbatim in prometheus.go**

```bash
grep -E 'federloom_blocked_ips|federloom_events_received_total|federloom_federation_peers' \
  internal/observability/prometheus.go
# Expected: all three metric names present
```

- [ ] **Step 5: Commit**

```bash
git add docs/getting-started.md
git commit -m "docs: rewrite getting-started as docker-first guide with per-stack sections"
```
