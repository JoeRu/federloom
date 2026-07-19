#!/usr/bin/env bash
# Smoke: inject a CrowdSec decision, expect it in the FederLoom score API and
# in the plain-text serve endpoint. Run via test/examples/run-smoke.sh.
set -euo pipefail
. "$(git rev-parse --show-toplevel)/test/examples/lib.sh"

IP=203.0.113.99

# LAPI may still be booting; retry the injection.
retry 20 3 docker compose exec -T crowdsec \
    cscli decisions add -i "$IP" -d 5m -R smoke-test

wait_for_score "http://127.0.0.1:9102" "$IP" 120

# Serve direction: the plain-text feed must include the IP.
retry 10 3 sh -c "curl -fsS http://127.0.0.1:9102/crowdsec/v1/decisions | grep -q '^$IP\$'"
echo "PASS: serve endpoint lists $IP"
