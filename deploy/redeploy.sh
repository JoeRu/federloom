#!/usr/bin/env bash
# Fresh redeploy of all SwarmGuard nodes.
# Wipes volumes (new peer IDs), pulls GHCR image, generates invite, patches configs,
# restarts all nodes, and runs smoke tests.
# Usage: ./deploy/redeploy.sh
# Requires: gh CLI, docker, jq, dig, curl, rsync, ssh access to all three nodes.
set -euo pipefail

IMAGE="ghcr.io/joeru/swarmguard:latest"
INVITE_FILE="honeypot-invite.json"

HONEYPOT_HOST="167.233.115.41"
HONEYPOT_PORT="2244"
HONEYPOT_USER="root"
HONEYPOT_CTR="swarmguard"
HONEYPOT_DIR="/opt/swarmguard"
HONEYPOT_COMPOSE="$HONEYPOT_DIR/deploy/honeypot/docker-compose.yml"

MAILCOW_HOST="mail.jru.me"
MAILCOW_PORT="2222"
MAILCOW_USER="joe"
MAILCOW_DIR="/opt/swarmguard"
MAILCOW_COMPOSE="$MAILCOW_DIR/deploy/mailcow/docker-compose.yml"

WP_HOST="d.jru.me"
WP_PORT="2222"
WP_USER="root"
WP_DIR="/opt/swarmguard"
WP_COMPOSE="$WP_DIR/deploy/wordpress/docker-compose.yml"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

hp() { ssh -p "$HONEYPOT_PORT" "$HONEYPOT_USER@$HONEYPOT_HOST" "$@"; }
mc() { ssh -l "$MAILCOW_USER" -p "$MAILCOW_PORT" "$MAILCOW_HOST" "$@"; }
wp() { ssh -l "$WP_USER" -p "$WP_PORT" "$WP_HOST" "$@"; }

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
  docker compose -f $HONEYPOT_COMPOSE down -v
  docker pull $IMAGE
  docker compose -f $HONEYPOT_COMPOSE up -d
"
echo "  Waiting 20s for swarmd to initialise..."
sleep 20

STATUS=$(hp "docker inspect --format='{{.State.Status}}' $HONEYPOT_CTR 2>/dev/null || echo missing")
if [[ "$STATUS" != "running" ]]; then
  echo "ERROR: $HONEYPOT_CTR status='$STATUS'"
  echo "  ssh -p $HONEYPOT_PORT $HONEYPOT_USER@$HONEYPOT_HOST docker logs $HONEYPOT_CTR"
  exit 1
fi
echo "  ✓ $HONEYPOT_CTR running"

# ─── Phase 2: Identity setup + invite generation ──────────────────────────────
echo ""
echo "══ Phase 2: Setup identity + generate invite ══"

hp "docker exec $HONEYPOT_CTR swarmctl setup \
  --config /etc/swarmguard/config.yaml \
  --label honeypot"

hp "docker exec $HONEYPOT_CTR swarmctl federation invite \
  --config /etc/swarmguard/config.yaml \
  --addr /dns4/swarmguard.jru.me/tcp/7700 \
  --out /tmp/invite.json"

hp "docker exec $HONEYPOT_CTR cat /tmp/invite.json" > "$INVITE_FILE"
echo "  ✓ invite written to $INVITE_FILE"

NEW_MULTIADDR=$(jq -r '.federation.bootstrap_peer' "$INVITE_FILE")
echo "  ✓ new multiaddr: $NEW_MULTIADDR"

# ─── Phase 3: Patch bootstrap_peers in all config files ───────────────────────
echo ""
echo "══ Phase 3: Patching config files ══"

for cfg in \
  "$REPO_ROOT/deploy/honeypot/config.yaml" \
  "$REPO_ROOT/deploy/mailcow/config.yaml" \
  "$REPO_ROOT/deploy/wordpress/config.yaml"; do
  # Replace old IP-based honeypot multiaddr
  sed -i "s|/ip4/167\.233\.115\.41/tcp/7700/p2p/[A-Za-z0-9]*|$NEW_MULTIADDR|g" "$cfg"
  # Replace DNS-based honeypot multiaddr (from a previous redeploy run)
  sed -i "s|/dns4/swarmguard\.jru\.me/tcp/7700/p2p/[A-Za-z0-9]*|$NEW_MULTIADDR|g" "$cfg"
  label=$(basename "$(dirname "$cfg")")
  echo "  ✓ patched $label/config.yaml"
done

# ─── Phase 4: Mailcow teardown + restart ──────────────────────────────────────
echo ""
echo "══ Phase 4: Mailcow — rsync, down -v, pull, up ══"

rsync -az --delete \
  --exclude='.git' --exclude='bin/' --exclude='data/' \
  --exclude='deploy/wordpress/config.local.yaml' \
  --exclude='deploy/mailcow/config.local.yaml' \
  -e "ssh -l $MAILCOW_USER -p $MAILCOW_PORT" \
  "$REPO_ROOT/" \
  "$MAILCOW_USER@$MAILCOW_HOST:$MAILCOW_DIR/"

mc "
  docker compose -f $MAILCOW_COMPOSE down -v
  docker pull $IMAGE
  docker compose -f $MAILCOW_COMPOSE up -d
"
echo "  ✓ mailcow restarted"

# ─── Phase 5: WordPress teardown + restart ────────────────────────────────────
echo ""
echo "══ Phase 5: WordPress — rsync, down -v, pull, up ══"

rsync -az --delete \
  --exclude='.git' --exclude='bin/' --exclude='data/' \
  --exclude='deploy/wordpress/config.local.yaml' \
  --exclude='deploy/mailcow/config.local.yaml' \
  -e "ssh -l $WP_USER -p $WP_PORT" \
  "$REPO_ROOT/" \
  "$WP_USER@$WP_HOST:$WP_DIR/"

wp "
  docker compose -f $WP_COMPOSE down -v
  docker pull $IMAGE
  docker compose -f $WP_COMPOSE up -d
"
echo "  ✓ wordpress restarted"

# ─── Phase 6: Wait for all nodes ──────────────────────────────────────────────
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
wait_metrics "honeypot"  "http://$HONEYPOT_HOST:9101/metrics" || BOOT_FAIL=1
wait_metrics "mailcow"   "http://100.120.31.14:9101/metrics"  || BOOT_FAIL=1
wait_metrics "wordpress" "http://100.92.58.24:9101/metrics"   || BOOT_FAIL=1

if [[ $BOOT_FAIL -ne 0 ]]; then
  echo "ERROR: one or more nodes failed to become healthy"
  exit 1
fi

# ─── Phase 7: Smoke test ──────────────────────────────────────────────────────
echo ""
echo "══ Phase 7: Smoke test ══"

PASS=0; FAIL=0

check_ok() {
  echo "  ✓ $1"
  ((PASS++)) || true
}
check_fail() {
  echo "  ✗ $1 — $2"
  ((FAIL++)) || true
}

# DNSBL: 2.0.0.127 is 127.0.0.2 reversed — always NXDOMAIN on a clean list.
# Empty reply = server answered and IP not listed (correct).
DNSBL=$(dig +short @swarmguard.jru.me -p 5353 \
  2.0.0.127.dnsbl.swarmguard.jru.me. A 2>/dev/null || echo "ERROR")
if [[ "$DNSBL" == "ERROR" ]]; then
  check_fail "honeypot DNSBL" "no response from swarmguard.jru.me:5353 (UDP)"
elif [[ -z "$DNSBL" ]]; then
  check_ok "honeypot DNSBL (NXDOMAIN for 127.0.0.2)"
else
  check_fail "honeypot DNSBL" "unexpected reply for 127.0.0.2: $DNSBL"
fi

# Federation: events received > 0 on mailcow and wordpress
for row in \
  "mailcow http://100.120.31.14:9101/metrics" \
  "wordpress http://100.92.58.24:9101/metrics"; do
  name="${row%% *}"; url="${row#* }"
  EVENTS=$(curl -sf "$url" \
    | grep '^swarmguard_events_received_total' \
    | awk '{sum+=$2} END{print int(sum)}')
  if [[ "${EVENTS:-0}" -gt 0 ]]; then
    check_ok "$name federation events (${EVENTS:-0} received)"
  else
    check_fail "$name federation events" "0 received — federation may need more time"
  fi
done

# Peer count > 0 on all three nodes
for row in \
  "honeypot  http://$HONEYPOT_HOST:9101/metrics" \
  "mailcow   http://100.120.31.14:9101/metrics" \
  "wordpress http://100.92.58.24:9101/metrics"; do
  name="${row%% *}"; url="${row#* }"
  PEERS=$(curl -sf "$url" \
    | grep '^swarmguard_federation_peers ' \
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
