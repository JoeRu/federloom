#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="docker compose -f $SCRIPT_DIR/docker-compose.dev.yml"

cleanup() {
    echo "--- cleaning up containers ---"
    $COMPOSE down -v 2>/dev/null || true
}
trap cleanup EXIT

echo "=== SwarmGuard smoke test ==="

# Build image from current source
echo "--- building image ---"
$COMPOSE build

# Start bootstrap only and extract its peer ID
echo "--- starting bootstrap node ---"
$COMPOSE up -d bootstrap

BOOTSTRAP_PEER_ID=""
for i in $(seq 1 20); do
    LINE=$($COMPOSE logs bootstrap 2>&1 | grep "^peer ID:" | head -1 || true)
    if [ -n "$LINE" ]; then
        BOOTSTRAP_PEER_ID=$(echo "$LINE" | awk '{print $NF}')
        break
    fi
    sleep 1
done

if [ -z "$BOOTSTRAP_PEER_ID" ]; then
    echo "FAIL: bootstrap did not start (no peer ID in logs after 20s)"
    exit 1
fi
echo "--- bootstrap peer ID: $BOOTSTRAP_PEER_ID ---"

# Start relay and leaves now that we know the bootstrap peer ID
echo "--- starting relay and leaf nodes ---"
BOOTSTRAP_PEER_ID="$BOOTSTRAP_PEER_ID" $COMPOSE up -d relay leaf1 leaf2 leaf3

# Wait for mesh to form and events to flow
echo "--- waiting 15s for mesh formation ---"
sleep 15

# Assert leaf2 and leaf3 received events from leaf1 (or leaf2/leaf3 from each other)
FAIL=0
for container in leaf2 leaf3; do
    if $COMPOSE logs "$container" 2>&1 | grep -q '"ip":"198.51.100.1"'; then
        echo "PASS: $container received events"
    else
        echo "FAIL: $container did not receive events"
        echo "--- $container logs ---"
        $COMPOSE logs "$container" 2>&1 | tail -20
        FAIL=1
    fi
done

if [ "$FAIL" -eq 0 ]; then
    echo "=== SMOKE TEST PASSED ==="
else
    echo "=== SMOKE TEST FAILED ==="
    exit 1
fi
