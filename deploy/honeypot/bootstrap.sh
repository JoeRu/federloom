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

echo "==> [2b/5] Copying .env to $SERVER:$REMOTE_DIR/deploy/honeypot/.env"
scp -P "$SSH_PORT" "$ENV_FILE" "$SSH_USER@$SERVER:$REMOTE_DIR/deploy/honeypot/.env"

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
