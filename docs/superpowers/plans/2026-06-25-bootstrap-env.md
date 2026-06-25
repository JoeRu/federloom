# Bootstrap Scripts Infrastructure Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract all hardcoded infrastructure info from the four deploy scripts into per-node `.env` files, remove the committed honeypot `.env` with a live token, rename all `swarmguard` references to `federloom`, and update smoketest metric names.

**Architecture:** In-place rewrite of all four scripts. Each bootstrap script gains a `source .env` guard at the top replacing every hardcoded IP/hostname/container-name with a `$VAR` reference. `redeploy.sh` uses a `load_env` function to source all three node `.env` files with prefixes. Per-node `.env.example` files are committed; actual `.env` files are gitignored.

**Tech Stack:** bash, rsync, ssh, docker — no new dependencies.

## Global Constraints

- All four scripts must pass `bash -n` (syntax check) after rewriting.
- No IP address (`\d+\.\d+\.\d+\.\d+`), hostname, SSH port, or container name may remain hardcoded in any script.
- Every `$VAR` used in a script must have a corresponding entry in that node's `.env.example`.
- `swarmguard` must not appear anywhere in the rewritten scripts (bouncer names, image refs, container refs, metric names).
- Metric names in smoketest: `federloom_events_received_total`, `federloom_federation_peers`.
- `deploy/honeypot/.env`, `deploy/mailcow/.env`, `deploy/wordpress/.env` must be listed in `.gitignore`.
- **Revoke token `e7fccf0a068b23e9a9e2fdae5cffc754498c679a522d77c55fb554dbcc9d12f7` in the honeypot CrowdSec instance before pushing.**
- `.env.example` values must use placeholder text (not real IPs), except container/network defaults that are not sensitive.

---

### Task 1: Remove committed token + update .gitignore

**Files:**
- Modify: `.gitignore`
- Modify: `deploy/honeypot/.env.example`
- Delete from tracking: `deploy/honeypot/.env`

**Interfaces:**
- Produces: `.env` files gitignored; committed `.env` untracked; `.env.example` updated.

- [ ] **Step 1: Add `.env` files to `.gitignore`**

Append to the root `.gitignore`:

```
# Per-node deploy secrets — copy from .env.example and fill in
deploy/honeypot/.env
deploy/mailcow/.env
deploy/wordpress/.env
```

- [ ] **Step 2: Untrack the committed honeypot `.env`**

```bash
git rm --cached deploy/honeypot/.env
```

Expected output: `rm 'deploy/honeypot/.env'`

- [ ] **Step 3: Update `deploy/honeypot/.env.example`**

Replace the entire file with:

```bash
# Copy to .env and fill in your values before running bootstrap.sh or redeploy.sh.
# Generate a token with: openssl rand -hex 32
FEDERLOOM_API_TOKEN=changeme
```

- [ ] **Step 4: Verify `.env` is now ignored**

```bash
git status deploy/honeypot/.env
```

Expected: `deploy/honeypot/.env` is not listed (ignored). If it shows as untracked, the `.gitignore` entry is not matching — check path.

- [ ] **Step 5: Commit**

```bash
git add .gitignore deploy/honeypot/.env.example
git commit -m "chore(deploy): remove committed honeypot .env token; gitignore all .env files"
```

---

### Task 2: Honeypot `.env.example` + rewrite `bootstrap.sh`

**Files:**
- Modify: `deploy/honeypot/.env.example` (expand from Task 1's stub)
- Modify: `deploy/honeypot/bootstrap.sh`

**Interfaces:**
- Produces: `deploy/honeypot/.env.example` with all vars; `bootstrap.sh` sources it.

- [ ] **Step 1: Write `deploy/honeypot/.env.example`**

Replace the entire file with:

```bash
# Copy to .env and fill in your values before running bootstrap.sh or redeploy.sh.
SERVER=your-honeypot-ip          # SSH hostname or IP
SSH_PORT=22                      # SSH port
SSH_USER=root                    # SSH user
REMOTE_DIR=/opt/federloom        # Remote deploy directory
PUBLIC_IP=your-honeypot-ip       # Node's public IP (used in multiaddr output)
CTR=federloom                    # FederLoom container name on this node
ADVERTISE_ADDR=/ip4/your-honeypot-ip/tcp/7700   # Public multiaddr for federation invites (use /dns4/your.domain/tcp/7700 if you have DNS)
DNSBL_ZONE=dnsbl.federloom.example.com.         # DNSBL zone for smoke test (trailing dot required)
BOOTSTRAP_PEER=                                  # Honeypot's own bootstrap peer multiaddr (fill after first run)
FEDERLOOM_API_TOKEN=changeme     # API token — generate with: openssl rand -hex 32
```

- [ ] **Step 2: Rewrite `deploy/honeypot/bootstrap.sh`**

Replace the entire file with:

```bash
#!/usr/bin/env bash
# Bootstraps the FederLoom honeypot stack on a fresh Ubuntu server.
# Usage: ./deploy/honeypot/bootstrap.sh
# Requires: rsync installed locally; SSH access configured in .env
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ENV_FILE="$SCRIPT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: $ENV_FILE not found."
  echo "  cp $SCRIPT_DIR/.env.example $SCRIPT_DIR/.env"
  echo "  # Edit .env with your server's values"
  exit 1
fi
# shellcheck source=.env.example
source "$ENV_FILE"

ssh_run() { ssh -p "$SSH_PORT" "$SSH_USER@$SERVER" "$@"; }

echo "==> [1/5] Installing Docker on $SERVER"
ssh_run '
  set -e
  if command -v docker &>/dev/null; then
    echo "Docker already installed: $(docker --version)"
    exit 0
  fi
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2
  systemctl enable --now docker
  echo "Installed: $(docker --version)"
'

echo "==> [2/5] Syncing repo to $SERVER:$REMOTE_DIR"
rsync -az --delete \
  --exclude='.git' --exclude='bin/' --exclude='data/' \
  --exclude='deploy/honeypot/.env' \
  --exclude='deploy/mailcow/.env' \
  --exclude='deploy/wordpress/.env' \
  --exclude='deploy/mailcow/config.local.yaml' \
  --exclude='deploy/wordpress/config.local.yaml' \
  -e "ssh -p $SSH_PORT" \
  "$REPO_ROOT/" \
  "$SSH_USER@$SERVER:$REMOTE_DIR/"

echo "==> [3/5] Pulling federloom image"
ssh_run "docker pull ghcr.io/joeru/federloom:latest"

echo "==> [4/5] Starting honeypot stack"
ssh_run "docker compose -f $REMOTE_DIR/deploy/honeypot/docker-compose.yml up -d"

echo "==> [5/5] Waiting 15s for federloomd to print peer ID..."
sleep 15

PEER_ID=$(ssh_run "docker logs $CTR 2>/dev/null | grep 'peer ID:' | tail -1 | awk '{print \$NF}'" || true)

echo ""
if [[ -z "$PEER_ID" ]]; then
  echo "WARNING: could not read peer ID from logs yet."
  echo "  Check: ssh -p $SSH_PORT $SSH_USER@$SERVER 'docker logs $CTR 2>&1 | head -30'"
else
  echo "Honeypot stack running on $SERVER"
  echo "  Peer ID : $PEER_ID"
  echo "  Bootstrap multiaddr: /ip4/$PUBLIC_IP/tcp/7700/p2p/$PEER_ID"
  echo ""
  echo "Next: start the client peer:"
  echo "  HONEYPOT_PEER_ADDR=/ip4/$PUBLIC_IP/tcp/7700/p2p/$PEER_ID \\"
  echo "    docker compose -f deploy/client/docker-compose.yml up"
fi
```

- [ ] **Step 3: Syntax-check the rewritten script**

```bash
bash -n deploy/honeypot/bootstrap.sh
```

Expected: no output (no syntax errors).

- [ ] **Step 4: Verify no hardcoded IPs or hostnames remain**

```bash
grep -En '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|nixos-|wordpress-nixos|swarmguard|swarmctl' \
  deploy/honeypot/bootstrap.sh
```

Expected: no matches. If any match, fix before committing.

- [ ] **Step 5: Commit**

```bash
git add deploy/honeypot/.env.example deploy/honeypot/bootstrap.sh
git commit -m "chore(deploy): extract honeypot infra vars to .env; rename swarmguard→federloom"
```

---

### Task 3: Mailcow `.env.example` + rewrite `bootstrap-mailcow.sh`

**Files:**
- Create: `deploy/mailcow/.env.example`
- Modify: `deploy/mailcow/bootstrap-mailcow.sh`

**Interfaces:**
- Produces: `deploy/mailcow/.env.example` with all vars; `bootstrap-mailcow.sh` sources it.

- [ ] **Step 1: Create `deploy/mailcow/.env.example`**

```bash
# Copy to .env and fill in your values before running bootstrap-mailcow.sh or redeploy.sh.
SERVER=mail.example.com                          # SSH hostname
SSH_PORT=2222                                    # SSH port
SSH_USER=joe                                     # SSH user
REMOTE_DIR=/opt/federloom                        # Remote deploy directory
PUBLIC_IP=your-mailcow-ip                        # Node's public IP (added to whitelist)
TAILSCALE_IP=100.x.x.x                          # Tailscale IP for metrics health check
CROWDSEC_CTR=mailcowdockerized-crowdsec-1        # CrowdSec container name
POSTFIX_CTR=mailcowdockerized-postfix-mailcow-1  # Postfix container name
DOVECOT_CTR=mailcowdockerized-dovecot-mailcow-1  # Dovecot container name
MAILCOW_NETWORK=172.22.1.0/24                    # Mailcow Docker network CIDR
DOCKER_BRIDGE=172.17.0.0/16                      # Docker default bridge CIDR
BOOTSTRAP_PEER=                                  # Honeypot bootstrap peer multiaddr
```

- [ ] **Step 2: Rewrite `deploy/mailcow/bootstrap-mailcow.sh`**

Replace the entire file with:

```bash
#!/usr/bin/env bash
# Bootstraps FederLoom on the Mailcow production server.
# Usage: ./deploy/mailcow/bootstrap-mailcow.sh
# Requires: rsync installed locally; SSH access configured in .env
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ENV_FILE="$SCRIPT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: $ENV_FILE not found."
  echo "  cp $SCRIPT_DIR/.env.example $SCRIPT_DIR/.env"
  echo "  # Edit .env with your server's values"
  exit 1
fi
# shellcheck source=.env.example
source "$ENV_FILE"

ssh_run()  { ssh -l "$SSH_USER" -p "$SSH_PORT" "$SERVER" "$@"; }
sudo_run() { ssh -l "$SSH_USER" -p "$SSH_PORT" "$SERVER" sudo "$@"; }

echo "==> [1/6] Registering CrowdSec bouncer on $SERVER"
sudo_run docker exec "$CROWDSEC_CTR" cscli bouncers delete federloom 2>/dev/null || true
RAW=$(sudo_run docker exec "$CROWDSEC_CTR" cscli bouncers add federloom 2>&1 || true)
API_KEY=$(echo "$RAW" | awk '/API key for/{found=1; next} found && /[A-Za-z0-9+\/=]/{gsub(/[[:space:]]/,""); print; exit}')

if [[ -z "$API_KEY" ]]; then
  echo ""
  echo "ERROR: could not extract CrowdSec API key automatically."
  echo "Run manually on the server:"
  echo "  sudo docker exec $CROWDSEC_CTR cscli bouncers add federloom"
  echo "Then set api_key in $REMOTE_DIR/deploy/mailcow/config.local.yaml and restart."
  echo ""
  echo "Continuing without CrowdSec ingest (enabled: false)."
  CROWDSEC_ENABLED="false"
  API_KEY=""
else
  echo "    Bouncer key registered."
  CROWDSEC_ENABLED="true"
fi

echo "==> [2/6] Syncing repo to $SERVER:$REMOTE_DIR"
rsync -az --delete \
  --exclude='.git' --exclude='bin/' --exclude='data/' \
  --exclude='deploy/honeypot/.env' \
  --exclude='deploy/mailcow/.env' \
  --exclude='deploy/wordpress/.env' \
  --exclude='deploy/mailcow/config.local.yaml' \
  --exclude='deploy/wordpress/config.local.yaml' \
  -e "ssh -l $SSH_USER -p $SSH_PORT" \
  "$REPO_ROOT/" \
  "$SSH_USER@$SERVER:$REMOTE_DIR/"

echo "==> [3/6] Pulling federloom image"
sudo_run docker pull ghcr.io/joeru/federloom:latest

echo "==> [4/6] Writing config.local.yaml (contains api_key — never committed)"
sudo_run bash -c "cat > $REMOTE_DIR/deploy/mailcow/config.local.yaml" <<EOF
# FederLoom config for Mailcow production node.
# Generated by bootstrap-mailcow.sh — do not commit (gitignored).
federation_mode: federated
store:
  dir: /var/lib/federloom
enforce:
  backend: ipset
  set_name: federloom
  chains:
    - DOCKER-USER
    - INPUT
  extra_whitelist:
    - ${PUBLIC_IP}
    - ${TAILSCALE_IP}
    - ${MAILCOW_NETWORK}
    - ${DOCKER_BRIDGE}
reputation:
  block_threshold: 75
  unblock_threshold: 60
  half_life: 168h
  decay_interval: 1h
  rules_file: /etc/federloom/rules.yaml
ingest:
  mailcow_logs:
    enabled: true
    postfix_container: ${POSTFIX_CTR}
    dovecot_container: ${DOVECOT_CTR}
    poll_interval: 30s
  spamtrap:
    enabled: false
    log_file: /var/log/federloom-spamtrap.log
    poll_interval: 5s
  crowdsec:
    enabled: ${CROWDSEC_ENABLED}
    lapi_url: "http://127.0.0.1:8080"
    api_key: "${API_KEY}"
    poll_interval: 30s
    enable_decisions: true
    enable_alerts: false
observability:
  prometheus_addr: ":9101"
api:
  addr: ":9102"
  purpose: "mail"
  taxonomy:
    mail:
      - smtp-*
      - imap-*
      - pop3-*
bootstrap_peers:
  - ${BOOTSTRAP_PEER}
EOF

echo "==> [5/6] Starting FederLoom"
sudo_run docker compose \
  -f "$REMOTE_DIR/deploy/mailcow/docker-compose.yml" \
  up -d

echo "==> [6/6] Waiting 10s for federloomd to print peer ID..."
sleep 10

PEER_ID=$(sudo_run docker logs federloom-mailcow 2>/dev/null \
  | grep 'peer ID:' | tail -1 | awk '{print $NF}' || true)

echo ""
if [[ -z "$PEER_ID" ]]; then
  echo "WARNING: could not read peer ID yet."
  echo "  Check: ssh -l $SSH_USER -p $SSH_PORT $SERVER 'sudo docker logs federloom-mailcow 2>&1 | head -30'"
else
  echo "FederLoom running on $SERVER"
  echo "  Peer ID  : $PEER_ID"
  echo "  Multiaddr: /ip4/$PUBLIC_IP/tcp/7700/p2p/$PEER_ID"
  echo ""
  echo "Federating with honeypot: $BOOTSTRAP_PEER"
  echo ""
  echo "NOTE: for full peering (inbound), open port 7700/tcp in NixOS firewall:"
  echo "  networking.firewall.allowedTCPPorts = [ 7700 ];"
fi
```

- [ ] **Step 3: Syntax-check**

```bash
bash -n deploy/mailcow/bootstrap-mailcow.sh
```

Expected: no output.

- [ ] **Step 4: Verify no hardcoded infra remains**

```bash
grep -En '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|nixos-mailcow|swarmguard|swarmctl|"joe"' \
  deploy/mailcow/bootstrap-mailcow.sh
```

Expected: no matches.

- [ ] **Step 5: Commit**

```bash
git add deploy/mailcow/.env.example deploy/mailcow/bootstrap-mailcow.sh
git commit -m "chore(deploy): extract mailcow infra vars to .env; rename swarmguard→federloom"
```

---

### Task 4: WordPress `.env.example` + rewrite `bootstrap-wordpress.sh`

**Files:**
- Create: `deploy/wordpress/.env.example`
- Modify: `deploy/wordpress/bootstrap-wordpress.sh`

**Interfaces:**
- Produces: `deploy/wordpress/.env.example` with all vars; `bootstrap-wordpress.sh` sources it.

- [ ] **Step 1: Create `deploy/wordpress/.env.example`**

```bash
# Copy to .env and fill in your values before running bootstrap-wordpress.sh or redeploy.sh.
SERVER=your-wordpress-host        # SSH hostname
SSH_PORT=2222                     # SSH port
SSH_USER=root                     # SSH user
REMOTE_DIR=/opt/federloom         # Remote deploy directory
PUBLIC_IP=your-wordpress-ip       # Node's public IP (added to whitelist)
TAILSCALE_IP=100.x.x.x           # Tailscale IP for metrics health check
CROWDSEC_CTR=crowdsec             # CrowdSec container name
CROWDSEC_LAPI_IP=172.21.0.3      # CrowdSec LAPI internal IP (in WP_NETWORK)
WP_NETWORK=172.21.0.0/16         # Traefik/WordPress Docker network CIDR
DOCKER_BRIDGE=172.17.0.0/16      # Docker default bridge CIDR
BOOTSTRAP_PEER=                   # Honeypot bootstrap peer multiaddr
```

- [ ] **Step 2: Rewrite `deploy/wordpress/bootstrap-wordpress.sh`**

Replace the entire file with:

```bash
#!/usr/bin/env bash
# Bootstraps FederLoom on the WordPress production server.
# Usage: ./deploy/wordpress/bootstrap-wordpress.sh
# Requires: rsync installed locally; SSH access configured in .env
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ENV_FILE="$SCRIPT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: $ENV_FILE not found."
  echo "  cp $SCRIPT_DIR/.env.example $SCRIPT_DIR/.env"
  echo "  # Edit .env with your server's values"
  exit 1
fi
# shellcheck source=.env.example
source "$ENV_FILE"

ssh_run() { ssh -l "$SSH_USER" -p "$SSH_PORT" "$SERVER" "$@"; }

echo "==> [1/7] Registering CrowdSec bouncer on $SERVER"
ssh_run docker exec "$CROWDSEC_CTR" cscli bouncers delete federloom 2>/dev/null || true
RAW=$(ssh_run docker exec "$CROWDSEC_CTR" cscli bouncers add federloom 2>&1 || true)
API_KEY=$(echo "$RAW" | awk '/API key for/{found=1; next} found && /[A-Za-z0-9+\/=]/{gsub(/[[:space:]]/,""); print; exit}')

if [[ -z "$API_KEY" ]]; then
  echo ""
  echo "ERROR: could not extract CrowdSec API key automatically."
  echo "Run manually on the server:"
  echo "  docker exec $CROWDSEC_CTR cscli bouncers add federloom"
  echo "Then set api_key in $REMOTE_DIR/deploy/wordpress/config.local.yaml and restart."
  echo ""
  echo "Continuing without CrowdSec ingest (enabled: false)."
  CROWDSEC_ENABLED="false"
  API_KEY=""
else
  echo "    Bouncer key registered."
  CROWDSEC_ENABLED="true"
fi

echo "==> [2/7] Syncing repo to $SERVER:$REMOTE_DIR"
rsync -az --delete \
  --exclude='.git' --exclude='bin/' --exclude='data/' \
  --exclude='deploy/honeypot/.env' \
  --exclude='deploy/mailcow/.env' \
  --exclude='deploy/wordpress/.env' \
  --exclude='deploy/mailcow/config.local.yaml' \
  --exclude='deploy/wordpress/config.local.yaml' \
  -e "ssh -l $SSH_USER -p $SSH_PORT" \
  "$REPO_ROOT/" \
  "$SSH_USER@$SERVER:$REMOTE_DIR/"

echo "==> [3/7] Pulling federloom image"
ssh_run docker pull ghcr.io/joeru/federloom:latest

echo "==> [4/7] Writing config.local.yaml (contains api_key — never committed)"
ssh_run bash -c "cat > $REMOTE_DIR/deploy/wordpress/config.local.yaml" <<EOF
# FederLoom config for WordPress production node.
# Generated by bootstrap-wordpress.sh — do not commit (gitignored).
federation_mode: federated
store:
  dir: /var/lib/federloom
enforce:
  backend: ipset
  set_name: federloom
  chains:
    - DOCKER-USER
    - INPUT
  extra_whitelist:
    - ${PUBLIC_IP}
    - ${WP_NETWORK}
    - ${DOCKER_BRIDGE}
reputation:
  block_threshold: 75
  unblock_threshold: 60
  half_life: 168h
  decay_interval: 1h
  rules_file: /etc/federloom/rules.yaml
ingest:
  crowdsec:
    enabled: ${CROWDSEC_ENABLED}
    lapi_url: "http://${CROWDSEC_LAPI_IP}:8080"
    api_key: "${API_KEY}"
    poll_interval: 30s
    enable_decisions: true
    enable_alerts: false
observability:
  prometheus_addr: ":9101"
  sqlite_path: "metrics.db"
  sqlite_retention: "720h"
api:
  addr: ":9102"
  purpose: "web"
  taxonomy:
    web:
      - http-*
bootstrap_peers:
  - ${BOOTSTRAP_PEER}
EOF

echo "==> [5/7] Starting FederLoom"
ssh_run docker compose \
  -f "$REMOTE_DIR/deploy/wordpress/docker-compose.yml" \
  up -d

echo "==> [6/7] Installing effectiveness exporter cron + textfile dir"
ssh_run bash -c "
  mkdir -p /var/lib/node_exporter/textfile
  chmod +x $REMOTE_DIR/deploy/wordpress/federloom-exporter.sh
  chmod +x $REMOTE_DIR/deploy/wordpress/effectiveness-report.sh
  (crontab -l 2>/dev/null | grep -v 'federloom-exporter'; echo '*/5 * * * * $REMOTE_DIR/deploy/wordpress/federloom-exporter.sh >> /var/log/federloom-exporter.log 2>&1') | crontab -
"
echo "    Cron installed; textfile dir ready at /var/lib/node_exporter/textfile"
echo "    NOTE: ensure node_exporter has --collector.textfile.directory=/var/lib/node_exporter/textfile/"

echo "==> [7/7] Waiting 10s for federloomd to print peer ID..."
sleep 10

PEER_ID=$(ssh_run docker logs federloom-wordpress 2>/dev/null \
  | grep 'peer ID:' | tail -1 | awk '{print $NF}' || true)

echo ""
if [[ -z "$PEER_ID" ]]; then
  echo "WARNING: could not read peer ID yet."
  echo "  Check: ssh -l $SSH_USER -p $SSH_PORT $SERVER 'docker logs federloom-wordpress 2>&1 | head -30'"
else
  echo "FederLoom running on $SERVER"
  echo "  Peer ID  : $PEER_ID"
  echo "  Multiaddr: /ip4/$PUBLIC_IP/tcp/7700/p2p/$PEER_ID"
  echo ""
  echo "Federating with honeypot: $BOOTSTRAP_PEER"
  echo ""
  echo "NOTE: for full peering (inbound), open port 7700/tcp in NixOS firewall:"
  echo "  networking.firewall.allowedTCPPorts = [ 7700 ];"
fi
```

- [ ] **Step 3: Syntax-check**

```bash
bash -n deploy/wordpress/bootstrap-wordpress.sh
```

Expected: no output.

- [ ] **Step 4: Verify no hardcoded infra remains**

```bash
grep -En '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|wordpress-nixos|swarmguard|swarmctl' \
  deploy/wordpress/bootstrap-wordpress.sh
```

Expected: no matches.

- [ ] **Step 5: Commit**

```bash
git add deploy/wordpress/.env.example deploy/wordpress/bootstrap-wordpress.sh
git commit -m "chore(deploy): extract wordpress infra vars to .env; rename swarmguard→federloom"
```

---

### Task 5: Rewrite `deploy/redeploy.sh`

**Files:**
- Modify: `deploy/redeploy.sh`

**Interfaces:**
- Consumes: `deploy/honeypot/.env`, `deploy/mailcow/.env`, `deploy/wordpress/.env` (sourced via `load_env`)
- Produces: fully rewritten `redeploy.sh` with no hardcoded infra, updated smoketest metrics, `federloom`-only naming.

- [ ] **Step 1: Rewrite `deploy/redeploy.sh`**

Replace the entire file with:

```bash
#!/usr/bin/env bash
# Fresh redeploy of all FederLoom nodes.
# Wipes volumes (new peer IDs), pulls GHCR image, generates invite, patches configs,
# restarts all nodes, and runs smoke tests.
# Usage: ./deploy/redeploy.sh
# Requires: gh CLI, docker, jq, dig, curl, rsync, ssh access to all three nodes.
# Each node's .env must exist: deploy/honeypot/.env, deploy/mailcow/.env, deploy/wordpress/.env
set -euo pipefail

IMAGE="ghcr.io/joeru/federloom:latest"
INVITE_FILE="honeypot-invite.json"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# load_env PREFIX FILE — read a .env file and expose each key as ${PREFIX}KEY
load_env() {
  local prefix="$1" file="$2"
  if [[ ! -f "$file" ]]; then
    echo "ERROR: $file not found."
    echo "  See: $(dirname "$file")/.env.example"
    exit 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// /}" ]] && continue
    local key="${line%%=*}"
    local val="${line#*=}"
    key="${key// /}"
    [[ -z "$key" ]] && continue
    val="${val%%  #*}"          # strip inline comment (double-space before #)
    val="${val%%	#*}"         # strip inline comment (tab before #)
    val="${val%"${val##*[![:space:]]}"}"  # rtrim whitespace
    printf -v "${prefix}${key}" '%s' "$val"
  done < "$file"
}

load_env "HONEYPOT_" "$SCRIPT_DIR/honeypot/.env"
load_env "MAILCOW_"  "$SCRIPT_DIR/mailcow/.env"
load_env "WP_"       "$SCRIPT_DIR/wordpress/.env"

hp() { ssh -p "$HONEYPOT_SSH_PORT" "$HONEYPOT_SSH_USER@$HONEYPOT_SERVER" "$@"; }
mc() { ssh -l "$MAILCOW_SSH_USER" -p "$MAILCOW_SSH_PORT" "$MAILCOW_SERVER" "$@"; }
wp() { ssh -l "$WP_SSH_USER"      -p "$WP_SSH_PORT"      "$WP_SERVER"      "$@"; }

# ─── Phase 0: Pre-flight ─────────────────────────────────────────────────────
echo ""
echo "══ Phase 0: Pre-flight checks ══"

CONCLUSION=$(gh run list --workflow=docker.yml --limit=1 --json conclusion \
  --jq '.[0].conclusion' 2>/dev/null || echo "unknown")
if [[ "$CONCLUSION" != "success" ]]; then
  echo "ERROR: latest docker workflow conclusion is '$CONCLUSION' (want 'success')"
  echo "  Check: gh run list --workflow=docker.yml"
  exit 1
fi
echo "  ✓ docker workflow: success"

if ! docker manifest inspect "$IMAGE" >/dev/null 2>&1; then
  echo "ERROR: cannot reach $IMAGE — check: docker login ghcr.io"
  exit 1
fi
echo "  ✓ image available: $IMAGE"

# ─── Phase 1: Honeypot teardown + restart ────────────────────────────────────
echo ""
echo "══ Phase 1: Honeypot — down -v, pull, up ══"

hp "
  docker compose -f $HONEYPOT_REMOTE_DIR/deploy/honeypot/docker-compose.yml down -v
  docker pull $IMAGE
  docker compose -f $HONEYPOT_REMOTE_DIR/deploy/honeypot/docker-compose.yml up -d
"
echo "  Waiting 20s for federloomd to initialise..."
sleep 20

STATUS=$(hp "docker inspect --format='{{.State.Status}}' $HONEYPOT_CTR 2>/dev/null || echo missing")
if [[ "$STATUS" != "running" ]]; then
  echo "ERROR: $HONEYPOT_CTR status='$STATUS'"
  echo "  ssh -p $HONEYPOT_SSH_PORT $HONEYPOT_SSH_USER@$HONEYPOT_SERVER docker logs $HONEYPOT_CTR"
  exit 1
fi
echo "  ✓ $HONEYPOT_CTR running"

# ─── Phase 2: Identity setup + invite generation ─────────────────────────────
echo ""
echo "══ Phase 2: Setup identity + generate invite ══"

hp "docker exec $HONEYPOT_CTR federloomctl setup \
  --config /etc/federloom/config.yaml \
  --label honeypot"

hp "docker exec $HONEYPOT_CTR federloomctl federation invite \
  --config /etc/federloom/config.yaml \
  --addr $HONEYPOT_ADVERTISE_ADDR \
  --out /tmp/invite.json"

hp "docker exec $HONEYPOT_CTR cat /tmp/invite.json" > "$INVITE_FILE"
echo "  ✓ invite written to $INVITE_FILE"

NEW_MULTIADDR=$(jq -r '.federation.bootstrap_peer' "$INVITE_FILE")
echo "  ✓ new multiaddr: $NEW_MULTIADDR"

# ─── Phase 3: Patch bootstrap_peers in all config files ──────────────────────
echo ""
echo "══ Phase 3: Patching config files ══"

for cfg in \
  "$REPO_ROOT/deploy/honeypot/config.yaml" \
  "$REPO_ROOT/deploy/mailcow/config.yaml" \
  "$REPO_ROOT/deploy/wordpress/config.yaml"; do
  sed -i "s|/ip4/[0-9.]\+/tcp/7700/p2p/[A-Za-z0-9]*|$NEW_MULTIADDR|g" "$cfg"
  sed -i "s|/dns4/[^/]*/tcp/7700/p2p/[A-Za-z0-9]*|$NEW_MULTIADDR|g" "$cfg"
  label=$(basename "$(dirname "$cfg")")
  echo "  ✓ patched $label/config.yaml"
done

# ─── Phase 4: Mailcow teardown + restart ─────────────────────────────────────
echo ""
echo "══ Phase 4: Mailcow — rsync, down -v, pull, up ══"

rsync -az --delete \
  --exclude='.git' --exclude='bin/' --exclude='data/' \
  --exclude='deploy/honeypot/.env' \
  --exclude='deploy/mailcow/.env' \
  --exclude='deploy/wordpress/.env' \
  --exclude='deploy/mailcow/config.local.yaml' \
  --exclude='deploy/wordpress/config.local.yaml' \
  -e "ssh -l $MAILCOW_SSH_USER -p $MAILCOW_SSH_PORT" \
  "$REPO_ROOT/" \
  "$MAILCOW_SSH_USER@$MAILCOW_SERVER:$MAILCOW_REMOTE_DIR/"

mc "
  docker compose -f $MAILCOW_REMOTE_DIR/deploy/mailcow/docker-compose.yml down -v
  docker pull $IMAGE
  docker compose -f $MAILCOW_REMOTE_DIR/deploy/mailcow/docker-compose.yml up -d
"
echo "  ✓ mailcow restarted"

# ─── Phase 5: WordPress teardown + restart ───────────────────────────────────
echo ""
echo "══ Phase 5: WordPress — rsync, down -v, pull, up ══"

rsync -az --delete \
  --exclude='.git' --exclude='bin/' --exclude='data/' \
  --exclude='deploy/honeypot/.env' \
  --exclude='deploy/mailcow/.env' \
  --exclude='deploy/wordpress/.env' \
  --exclude='deploy/mailcow/config.local.yaml' \
  --exclude='deploy/wordpress/config.local.yaml' \
  -e "ssh -l $WP_SSH_USER -p $WP_SSH_PORT" \
  "$REPO_ROOT/" \
  "$WP_SSH_USER@$WP_SERVER:$WP_REMOTE_DIR/"

wp "
  docker compose -f $WP_REMOTE_DIR/deploy/wordpress/docker-compose.yml down -v
  docker pull $IMAGE
  docker compose -f $WP_REMOTE_DIR/deploy/wordpress/docker-compose.yml up -d
"
echo "  ✓ wordpress restarted"

# ─── Phase 6: Wait for all nodes ─────────────────────────────────────────────
echo ""
echo "══ Phase 6: Waiting for metrics endpoints (up to 120s each) ══"

wait_metrics() {
  local name="$1" url="$2"
  local deadline=$((SECONDS + 120))
  while [[ $SECONDS -lt $deadline ]]; do
    if curl -sf --max-time 5 "$url" >/dev/null 2>&1; then
      echo "  ✓ $name metrics up"
      return 0
    fi
    sleep 5
  done
  echo "  ✗ $name metrics timeout after 120s"
  return 1
}

BOOT_FAIL=0
wait_metrics "honeypot"  "http://$HONEYPOT_PUBLIC_IP:9101/metrics"   || BOOT_FAIL=1
wait_metrics "mailcow"   "http://$MAILCOW_TAILSCALE_IP:9101/metrics" || BOOT_FAIL=1
wait_metrics "wordpress" "http://$WP_TAILSCALE_IP:9101/metrics"      || BOOT_FAIL=1

if [[ $BOOT_FAIL -ne 0 ]]; then
  echo "ERROR: one or more nodes failed to become healthy"
  exit 1
fi

# ─── Phase 7: Smoke test ─────────────────────────────────────────────────────
echo ""
echo "══ Phase 7: Smoke test ══"

PASS=0; FAIL=0

check_ok()   { echo "  ✓ $1"; ((PASS++)) || true; }
check_fail() { echo "  ✗ $1 — $2"; ((FAIL++)) || true; }

# DNSBL: 2.0.0.127 is 127.0.0.2 reversed — always NXDOMAIN on a clean list.
DNSBL=$(dig +short @"$HONEYPOT_SERVER" -p 5353 \
  2.0.0.127."$HONEYPOT_DNSBL_ZONE" A 2>/dev/null || echo "ERROR")
if [[ "$DNSBL" == "ERROR" ]]; then
  check_fail "honeypot DNSBL" "no response from $HONEYPOT_SERVER:5353 (UDP)"
elif [[ -z "$DNSBL" ]]; then
  check_ok "honeypot DNSBL (NXDOMAIN for 127.0.0.2)"
else
  check_fail "honeypot DNSBL" "unexpected reply for 127.0.0.2: $DNSBL"
fi

# Federation: events received > 0 on mailcow and wordpress
for row in \
  "mailcow http://$MAILCOW_TAILSCALE_IP:9101/metrics" \
  "wordpress http://$WP_TAILSCALE_IP:9101/metrics"; do
  name="${row%% *}"; url="${row#* }"
  EVENTS=$(curl -sf "$url" \
    | grep '^federloom_events_received_total' \
    | awk '{sum+=$2} END{print int(sum)}')
  if [[ "${EVENTS:-0}" -gt 0 ]]; then
    check_ok "$name federation events (${EVENTS:-0} received)"
  else
    check_fail "$name federation events" "0 received — federation may need more time"
  fi
done

# Peer count > 0 on all three nodes
for row in \
  "honeypot  http://$HONEYPOT_PUBLIC_IP:9101/metrics" \
  "mailcow   http://$MAILCOW_TAILSCALE_IP:9101/metrics" \
  "wordpress http://$WP_TAILSCALE_IP:9101/metrics"; do
  name="${row%% *}"; url="${row#* }"
  PEERS=$(curl -sf "$url" \
    | grep '^federloom_federation_peers ' \
    | awk '{print int($2)}')
  if [[ "${PEERS:-0}" -gt 0 ]]; then
    check_ok "$name peers (${PEERS:-0})"
  else
    check_fail "$name peers" "0 — not yet connected"
  fi
done

echo ""
echo "────────────────────────────────────"
printf "  Passed: %-3d  Failed: %d\n" "$PASS" "$FAIL"
echo "────────────────────────────────────"
echo ""

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi

echo "All checks passed."
echo "  Invite   : $INVITE_FILE"
echo "  Multiaddr: $NEW_MULTIADDR"
echo ""
echo "Commit the updated config files:"
echo "  git add deploy/honeypot/config.yaml deploy/mailcow/config.yaml deploy/wordpress/config.yaml"
echo "  git commit -m 'chore(deploy): update bootstrap_peers to new honeypot peer ID'"
```

- [ ] **Step 2: Syntax-check**

```bash
bash -n deploy/redeploy.sh
```

Expected: no output.

- [ ] **Step 3: Verify no hardcoded infra remains**

```bash
grep -En '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|mail\.jru\.me|d\.jru\.me|swarmguard|swarmctl|swarmguard\.jru\.me' \
  deploy/redeploy.sh
```

Expected: no matches. The only IP-like patterns allowed are inside comments or as part of example output strings.

- [ ] **Step 4: Verify all `$VAR` references in redeploy.sh exist in the sourced .env.example files**

```bash
# Extract all $VAR_NAME references from redeploy.sh (after load_env)
grep -oE '\$\{?(HONEYPOT|MAILCOW|WP)_[A-Z_]+\}?' deploy/redeploy.sh \
  | sed 's/[${}]//g' | sort -u
```

Cross-check each result against the three `.env.example` files. Every `HONEYPOT_X` must have `X` in `deploy/honeypot/.env.example`, etc.

- [ ] **Step 5: Commit**

```bash
git add deploy/redeploy.sh
git commit -m "chore(deploy): extract all infra vars to .env in redeploy.sh; update smoketest metrics"
```
