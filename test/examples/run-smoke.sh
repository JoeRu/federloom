#!/usr/bin/env bash
# Smoke-runner for docker examples.
# Usage: test/examples/run-smoke.sh [example-dir ...]
# With no args, runs every dir under examples/ that contains a smoke.sh.
# Contract per example dir: docker compose up -d && ./smoke.sh; down -v always.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "--- building federloom image from current source ---"
docker build -t ghcr.io/joeru/federloom:latest \
    -f "$REPO_ROOT/deploy/docker/Dockerfile" "$REPO_ROOT"

dirs=("$@")
if [ ${#dirs[@]} -eq 0 ]; then
    while IFS= read -r s; do dirs+=("$(dirname "$s")"); done \
        < <(find "$REPO_ROOT/examples" -name smoke.sh 2>/dev/null | sort)
fi
if [ ${#dirs[@]} -eq 0 ]; then
    echo "no smoke-testable examples found — nothing to do"
    exit 0
fi

fail=0
for dir in "${dirs[@]}"; do
    echo "=== smoke: $dir ==="
    if (
        cd "$dir"
        trap 'docker compose down -v >/dev/null 2>&1 || true' EXIT
        docker compose up -d
        ./smoke.sh
    ); then
        echo "=== PASS: $dir ==="
    else
        echo "=== FAIL: $dir ==="
        fail=1
    fi
done
exit $fail
