# Bootstrap Scripts — Infrastructure Extraction Design

**Date:** 2026-06-25
**Status:** Approved

## Goal

Remove all hardcoded infrastructure information (IPs, hostnames, SSH users/ports,
container names, internal CIDRs) from the committed bootstrap scripts, replace
with per-node `.env` files (gitignored), update all `swarmguard` → `federloom`
renames throughout the scripts, and update the smoketest metric names to match
the renamed metrics. Remove the committed `deploy/honeypot/.env` that contains
a live API token.

## Scope

Four files rewritten in-place:
- `deploy/honeypot/bootstrap.sh`
- `deploy/mailcow/bootstrap-mailcow.sh`
- `deploy/wordpress/bootstrap-wordpress.sh`
- `deploy/redeploy.sh`

Three `.env.example` files created/updated (committed):
- `deploy/honeypot/.env.example`
- `deploy/mailcow/.env.example`
- `deploy/wordpress/.env.example`

Three `.env` files gitignored (never committed):
- `deploy/honeypot/.env`
- `deploy/mailcow/.env`
- `deploy/wordpress/.env`

## Variables extracted per node

### deploy/honeypot/.env.example

```bash
SERVER=167.233.115.41           # SSH hostname or IP
SSH_PORT=2244                   # SSH port
SSH_USER=root                   # SSH user
REMOTE_DIR=/opt/federloom       # Remote deploy directory
PUBLIC_IP=167.233.115.41        # Node's public IP (used in multiaddr output)
BOOTSTRAP_PEER=                 # Honeypot's own bootstrap peer multiaddr (set after first run)
DNSBL_ZONE=dnsbl.federloom.jru.me.  # DNSBL zone for smoke test
```

### deploy/mailcow/.env.example

```bash
SERVER=mail.jru.me              # SSH hostname
SSH_PORT=2222                   # SSH port
SSH_USER=joe                    # SSH user
REMOTE_DIR=/opt/federloom       # Remote deploy directory
PUBLIC_IP=135.181.91.151        # Node's public IP (used in whitelist + multiaddr)
TAILSCALE_IP=100.120.31.14      # Tailscale IP (used in metrics health check)
CROWDSEC_CTR=mailcowdockerized-crowdsec-1   # CrowdSec container name
POSTFIX_CTR=mailcowdockerized-postfix-mailcow-1
DOVECOT_CTR=mailcowdockerized-dovecot-mailcow-1
MAILCOW_NETWORK=172.22.1.0/24   # Mailcow Docker network CIDR
DOCKER_BRIDGE=172.17.0.0/16     # Docker default bridge CIDR
BOOTSTRAP_PEER=                 # Honeypot bootstrap peer multiaddr
```

### deploy/wordpress/.env.example

```bash
SERVER=d.jru.me                 # SSH hostname
SSH_PORT=2222                   # SSH port
SSH_USER=root                   # SSH user
REMOTE_DIR=/opt/federloom       # Remote deploy directory
PUBLIC_IP=65.108.62.108         # Node's public IP (used in whitelist + multiaddr)
TAILSCALE_IP=100.92.58.24       # Tailscale IP (used in metrics health check)
CROWDSEC_CTR=crowdsec           # CrowdSec container name
CROWDSEC_LAPI_IP=172.21.0.3     # CrowdSec LAPI internal IP
WP_NETWORK=172.21.0.0/16        # Traefik/WordPress Docker network CIDR
DOCKER_BRIDGE=172.17.0.0/16     # Docker default bridge CIDR
BOOTSTRAP_PEER=                 # Honeypot bootstrap peer multiaddr
```

## Script header pattern (all bootstrap scripts)

```bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: $ENV_FILE not found."
  echo "  cp $SCRIPT_DIR/.env.example $SCRIPT_DIR/.env"
  echo "  # Edit .env with your server's values"
  exit 1
fi
# shellcheck source=.env.example
source "$ENV_FILE"
```

## redeploy.sh approach

`redeploy.sh` has no own `.env`. It sources each node's `.env` and prefixes
variables to avoid collisions:

```bash
load_env() {
  local prefix="$1" file="$2"
  if [[ ! -f "$file" ]]; then
    echo "ERROR: $file not found. See ${file%.env}.env.example"
    exit 1
  fi
  while IFS='=' read -r key val; do
    [[ "$key" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$key" ]] && continue
    key="${key// /}"
    printf -v "${prefix}${key}" '%s' "${val}"
  done < "$file"
}

load_env "HONEYPOT_" "$SCRIPT_DIR/honeypot/.env"
load_env "MAILCOW_"  "$SCRIPT_DIR/mailcow/.env"
load_env "WP_"       "$SCRIPT_DIR/wordpress/.env"
```

Variables then accessed as `$HONEYPOT_SERVER`, `$MAILCOW_PUBLIC_IP`, etc.

## Renames (swarmguard → federloom)

| Old | New |
|-----|-----|
| `swarmguard` (bouncer name in cscli) | `federloom` |
| `ghcr.io/joeru/swarmguard:latest` | `ghcr.io/joeru/federloom:latest` |
| `swarmguard-mailcow` (container) | `federloom-mailcow` |
| `swarmctl` | `federloomctl` |
| `swarmguard.jru.me` (DNSBL hostname) | `$HONEYPOT_DNSBL_ZONE` (from env) |
| `swarmguard_events_received_total` (metric) | `federloom_events_received_total` |

## Smoketest updates (redeploy.sh Phase 7)

- DNSBL check: uses `$HONEYPOT_DNSBL_ZONE` from env
- Metrics URLs: use `$HONEYPOT_PUBLIC_IP`, `$MAILCOW_TAILSCALE_IP`, `$WP_TAILSCALE_IP`
- Event metric: `federloom_events_received_total`
- Peer metric: `federloom_federation_peers` (already correct)

## Committed token cleanup

1. `git rm --cached deploy/honeypot/.env` — stop tracking the file
2. **Revoke the token** `e7fccf0a...` in the honeypot CrowdSec instance before pushing
3. Add `deploy/honeypot/.env`, `deploy/mailcow/.env`, `deploy/wordpress/.env` to root `.gitignore`
4. Update `deploy/honeypot/.env.example`: rename `SWARMGUARD_API_TOKEN` → `FEDERLOOM_API_TOKEN`, value `changeme`

## Out of scope

- Actual metric renames in Go code (separate task)
- History rewrite to scrub the token from past commits (token revocation is sufficient)
- Changes to `deploy/client/` or `deploy/grafana/`
