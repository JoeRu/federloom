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
