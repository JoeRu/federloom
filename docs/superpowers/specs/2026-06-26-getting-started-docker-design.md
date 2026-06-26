# Getting Started (Docker) — Design Spec

## Goal

Replace `docs/getting-started.md` with a Docker-first guide aimed at
self-hosters who may run any combination of Mailcow, WordPress/nginx,
CrowdSec, and fail2ban. The reader knows nothing about FederLoom before
opening this page. After following the relevant section they have a running
node ingesting threat signals and (optionally) federating with peers.

## Audience and reading model

Generic self-hoster: may have Mailcow, WordPress, CrowdSec, fail2ban, or
none of the above. Opens the guide, reads the one-paragraph intro, follows
the decision table to their section, copies the commands, verifies the node
is healthy. They do not read sections that do not apply to them.

## Document structure

File: `docs/getting-started.md` (full replacement of current content)

```
# Getting Started with FederLoom

[one-paragraph intro]

## Prerequisites
## Pick your stack  ← decision table
## Standalone node
## Mailcow
## WordPress / generic web
## CrowdSec standalone
## fail2ban
## Federation (once running)
```

---

## Section content specifications

### Intro paragraph (~80 words)

FederLoom is a federated, trust-weighted IP blocklist you self-host as a
Docker container. It ingests threat signals from your existing tools
(Mailcow, CrowdSec, fail2ban, WordPress logs), scores IPs locally using a
configurable rules engine, and optionally shares reputation with peers you
trust — peer-to-peer, no central authority. This guide covers the Docker
path; no build tools required. At the end you will have a running container
blocking IPs and exposing Prometheus metrics at `:9101/metrics`.

### Prerequisites

- Docker Engine ≥ 24 and Compose v2 (`docker compose`, not `docker-compose`)
- SSH access to the target server (bootstrap scripts run locally and SSH in)
- `rsync` installed locally
- Port 7700/tcp open on the server if you want inbound federation peers
  (outbound-only peering works without it)

No Go toolchain needed — image is pulled from `ghcr.io/joeru/federloom:latest`.

### Pick your stack — decision table

| My setup | Jump to |
|---|---|
| Mailcow mail server | [§ Mailcow](#mailcow) |
| WordPress / nginx / traefik + CrowdSec | [§ WordPress / generic web](#wordpress--generic-web) |
| Any server running CrowdSec (no Mailcow) | [§ CrowdSec standalone](#crowdsec-standalone) |
| Any server running fail2ban in Docker | [§ fail2ban](#fail2ban) |
| Just want to try it / standalone sensor | [§ Standalone node](#standalone-node) |

---

### Section template (all five sections follow this exact shape)

Each section has four subsections:

1. **What you get** — one sentence describing what the running node does.
2. **Configure `.env`** — copy from `.env.example`, explanation table for
   every variable, and any "find this value" hints.
3. **Run** — the single bootstrap command.
4. **Verify** — `curl` the metrics endpoint and what healthy output looks
   like (specific metric names and expected non-zero values).

---

### § Standalone node

**What you get:** A FederLoom node that listens on port 7700, scores IPs
from its own sensors (cowrie SSH honeypot + OpenCanary), and exposes metrics.
No ingest from external tools.

**`.env` file:** `deploy/honeypot/.env` (copied from `.env.example`)

| Variable | What it is | Example |
|---|---|---|
| `SERVER` | SSH hostname or IP of the server | `203.0.113.10` |
| `SSH_PORT` | SSH port | `22` |
| `SSH_USER` | SSH user | `root` |
| `REMOTE_DIR` | Deploy path on the server | `/opt/federloom` |
| `PUBLIC_IP` | Server's public IP (used in multiaddr output) | `203.0.113.10` |
| `CTR` | Container name | `federloom` |
| `ADVERTISE_ADDR` | Public multiaddr for federation invites | `/ip4/203.0.113.10/tcp/7700` or `/dns4/your.domain/tcp/7700` |
| `DNSBL_ZONE` | DNSBL zone suffix (trailing dot required) | `dnsbl.example.com.` |
| `BOOTSTRAP_PEER` | Leave empty on first run | `` |
| `FEDERLOOM_API_TOKEN` | API bearer token — generate with `openssl rand -hex 32` | `e7fc...` |

**Run:**
```bash
cp deploy/honeypot/.env.example deploy/honeypot/.env
# edit .env with your values
bash deploy/honeypot/bootstrap.sh
```

**Verify:** After bootstrap prints the peer ID, check the metrics endpoint
(replace `YOUR_IP` with `PUBLIC_IP` from your `.env`):
```bash
curl -s http://YOUR_IP:9101/metrics | grep federloom_blocked_ips_total
# Healthy: returns a non-negative integer (0 is fine on a fresh node)
```

---

### § Mailcow

**What you get:** FederLoom runs as a sidecar alongside Mailcow. It reads
Postfix and Dovecot logs for brute-force and spam signals, pulls CrowdSec
LAPI decisions, and blocks IPs via ipset on the host kernel. Port 7700
enables outbound federation.

**`.env` file:** `deploy/mailcow/.env` (copied from `.env.example`)

| Variable | What it is | How to find it |
|---|---|---|
| `SERVER` | SSH hostname | `mail.example.com` |
| `SSH_PORT` | SSH port | typically `2222` for Mailcow servers |
| `SSH_USER` | SSH user | user with sudo + docker group |
| `REMOTE_DIR` | Deploy path on server | `/opt/federloom` |
| `PUBLIC_IP` | Server's public IP | `dig +short mail.example.com` |
| `TAILSCALE_IP` | Tailscale IP (if used) for Prometheus scraping | `100.x.x.x` — skip if no Tailscale |
| `CROWDSEC_CTR` | CrowdSec container name | `docker ps \| grep crowdsec` on the server |
| `POSTFIX_CTR` | Postfix container name | `docker ps \| grep postfix` on the server |
| `DOVECOT_CTR` | Dovecot container name | `docker ps \| grep dovecot` on the server |
| `MAILCOW_NETWORK` | Mailcow Docker network CIDR (whitelisted) | `docker network inspect mailcowdockerized_mailcow-network` |
| `DOCKER_BRIDGE` | Docker bridge CIDR (whitelisted) | `172.17.0.0/16` default |
| `BOOTSTRAP_PEER` | Peer to connect to on startup | leave empty for solo; set to honeypot multiaddr to federate |

Note: `/opt/federloom` must exist and be writable by `SSH_USER` before running
bootstrap. Create it with `ssh USER@SERVER 'sudo mkdir -p /opt/federloom && sudo chown USER /opt/federloom'`.

**Run:**
```bash
cp deploy/mailcow/.env.example deploy/mailcow/.env
# edit .env with your values
bash deploy/mailcow/bootstrap-mailcow.sh
```

**Verify:**
```bash
# From a machine that can reach the Tailscale/LAN IP, or on the server itself:
curl -s http://SERVER:9101/metrics | grep -E 'federloom_blocked|federation_peers'
# Healthy: blocked_ips >= 0, federation_peers >= 0
# After a few minutes: check CrowdSec events arriving:
# federloom_events_received_total{reason="..."} > 0
```

---

### § WordPress / generic web

**What you get:** FederLoom runs alongside your web stack. It reads CrowdSec
LAPI decisions (HTTP scanning, exploit attempts, bruteforce), blocks IPs via
ipset, and federates with peers. Also installs an effectiveness exporter cron
that writes node_exporter textfile metrics.

**`.env` file:** `deploy/wordpress/.env` (copied from `.env.example`)

| Variable | What it is | How to find it |
|---|---|---|
| `SERVER` | SSH hostname | `d.example.com` |
| `SSH_PORT` | SSH port | `22` or `2222` |
| `SSH_USER` | SSH user | `root` or user with docker group |
| `REMOTE_DIR` | Deploy path on server | `/opt/federloom` |
| `PUBLIC_IP` | Server's public IP | `dig +short d.example.com` |
| `TAILSCALE_IP` | Tailscale IP for Prometheus (optional) | `100.x.x.x` |
| `CROWDSEC_CTR` | CrowdSec container name | `docker ps \| grep crowdsec` |
| `CROWDSEC_LAPI_IP` | CrowdSec LAPI IP inside the Docker network | `docker inspect crowdsec \| grep IPAddress` |
| `WP_NETWORK` | Your web stack's Docker network CIDR (whitelisted) | `docker network inspect <network>` |
| `DOCKER_BRIDGE` | Docker bridge CIDR (whitelisted) | `172.17.0.0/16` default |
| `BOOTSTRAP_PEER` | Peer to connect to on startup | leave empty for solo; set to honeypot multiaddr to federate |

**Run:**
```bash
cp deploy/wordpress/.env.example deploy/wordpress/.env
# edit .env with your values
bash deploy/wordpress/bootstrap-wordpress.sh
```

**Verify:**
```bash
curl -s http://SERVER:9101/metrics | grep -E 'federloom_blocked|crowdsec'
# federloom_blocked_ips_total >= 0
# After CrowdSec events arrive: federloom_events_received_total{...} > 0
```

---

### § CrowdSec standalone

**What you get:** FederLoom as a CrowdSec bouncer on any server running
CrowdSec — without Mailcow or a web stack. Pulls decisions from the local
LAPI and blocks IPs via ipset. Uses the WordPress bootstrap path with a
simplified config (no web-specific taxonomy).

This section applies when:
- Your server runs CrowdSec but is not a Mailcow or WordPress host
- You want FederLoom to act as a federated enforcement layer for CrowdSec decisions

**Setup:** Follow the [§ WordPress / generic web](#wordpress--generic-web) steps
with these adjustments to `.env`:

| Variable | Adjust to |
|---|---|
| `CROWDSEC_LAPI_IP` | `127.0.0.1` if CrowdSec runs on the host (not in Docker) |
| `WP_NETWORK` | your server's main Docker network, or `172.17.0.0/16` if no custom networks |
| `CROWDSEC_CTR` | your CrowdSec container name |

Use the same `bootstrap-wordpress.sh` — the "wordpress" label is cosmetic;
the generated config works for any CrowdSec-backed node.

---

### § fail2ban

**What you get:** FederLoom reads bans from a fail2ban container via
`docker exec <container> fail2ban-client banned`, maps jail names to reason
codes, and scores IPs accordingly.

**Supported jails (built-in mappings):**

| fail2ban jail | FederLoom reason |
|---|---|
| `sshd`, `ssh` | `ssh-auth-bruteforce` |
| `postfix`, `postfix-sasl` | `smtp-auth-bruteforce` |
| `dovecot` | `imap-auth-bruteforce` |
| `nginx-http-auth`, `apache-auth` | `http-auth-bruteforce` |
| `wordpress` | `http-wp-bruteforce` |
| `recidive` | `recidive` |
| `<anything>-*` | matched by prefix (e.g. `postfix-*` → `smtp-auth-bruteforce`) |

**Config snippet** — add to your `config.local.yaml` (or the example config):
```yaml
ingest:
  fail2ban:
    enabled: true
    container: fail2ban        # docker container name running fail2ban
    poll_interval: 30s
```

**No dedicated bootstrap script exists for fail2ban-only nodes.** The simplest
path is to use the standalone node section and add the `ingest.fail2ban` block
to the generated `config.local.yaml` after running bootstrap:

```bash
# After bootstrap.sh completes, SSH in and edit the config:
ssh USER@SERVER "echo '
ingest:
  fail2ban:
    enabled: true
    container: fail2ban
    poll_interval: 30s
' >> /opt/federloom/deploy/honeypot/config.yaml && docker restart federloom"
```

Or set `container` to match your actual container name (`docker ps | grep fail2ban`).

**Verify:**
```bash
curl -s http://SERVER:9101/metrics | grep 'federloom_events_received_total.*bruteforce'
# Should show counts after the first poll_interval (30s)
```

---

### § Federation (once running)

Once your node is healthy, connect it to peers:

- **Solo federation (outbound only):** set `BOOTSTRAP_PEER` in your `.env`
  to another operator's multiaddr (printed at the end of their bootstrap run)
  and re-run the bootstrap script. Port 7700 does not need to be open for
  outbound-only federation.
- **Full mesh (inbound + outbound):** open port 7700/tcp in your firewall.
  Share your multiaddr (printed by bootstrap: `/ip4/YOUR_IP/tcp/7700/p2p/12D3Koo…`)
  with peer operators.

For trust setup, invitation exchange, and weight tuning see
[`docs/federation-guide.md`](federation-guide.md).

---

## What the current getting-started.md covers that must move

The existing `getting-started.md` covers federation setup (Options A/B/C),
key management, and `federloomctl` commands. These are not deleted — they
move to a **"Binary / development path"** appendix at the bottom of the new
document (collapsed or clearly marked as "not needed for Docker installs").
The key management reference table stays inline as a collapsed section or
footnote so Docker users can find it if they need to inspect keys.

## Files touched

- `docs/getting-started.md` — full rewrite (preserve git history, same file)
- No other files changed

## Out of scope

- No new bootstrap scripts
- No changes to docker-compose files
- No changes to `.env.example` files
- The fail2ban section documents the existing plugin; no new config keys
