#!/usr/bin/env bash
# Bootstraps the honeypot stack on a fresh Ubuntu server.
# Usage: ./deploy/honeypot/bootstrap.sh
# Requires: ssh access to 167.233.115.41 on port 2244 as root, rsync installed locally.
set -euo pipefail

SERVER="167.233.115.41"
SSH_PORT="2244"
SSH_USER="root"
REMOTE_DIR="/opt/federloom"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

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
  --exclude='deploy/wordpress/config.local.yaml' \
  --exclude='deploy/mailcow/config.local.yaml' \
  -e "ssh -p $SSH_PORT" \
  "$REPO_ROOT/" \
  "$SSH_USER@$SERVER:$REMOTE_DIR/"

echo "==> [3/5] Pulling federloom image"
ssh_run "docker pull ghcr.io/joeru/federloom:latest"

echo "==> [4/5] Starting honeypot stack"
ssh_run "docker compose -f $REMOTE_DIR/deploy/honeypot/docker-compose.yml up -d"

echo "==> [5/5] Waiting 15s for swarmd to print peer ID..."
sleep 15

PEER_ID=$(ssh_run "docker logs federloom 2>/dev/null | grep 'peer ID:' | tail -1 | awk '{print \$NF}'" || true)

echo ""
if [[ -z "$PEER_ID" ]]; then
  echo "WARNING: could not read peer ID from logs yet."
  echo "  Check: ssh -p $SSH_PORT $SSH_USER@$SERVER 'docker logs swarmguard 2>&1 | head -30'"
else
  echo "Honeypot stack running on $SERVER"
  echo "  Peer ID : $PEER_ID"
  echo "  Bootstrap multiaddr: /ip4/$SERVER/tcp/7700/p2p/$PEER_ID"
  echo ""
  echo "Next: start the client peer:"
  echo "  HONEYPOT_PEER_ADDR=/ip4/$SERVER/tcp/7700/p2p/$PEER_ID \\"
  echo "    docker compose -f deploy/client/docker-compose.yml up"
fi
