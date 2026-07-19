#!/usr/bin/env bash
# Smoke: inject a CrowdSec decision, expect it in the FederLoom score API.
# (The serve-direction /crowdsec/v1/decisions check lives in the crowdsec
# example — no need to repeat it here.) Run via test/examples/run-smoke.sh.
set -euo pipefail
. "$(git rev-parse --show-toplevel)/test/examples/lib.sh"

IP=203.0.113.99

# LAPI may still be booting; retry the injection.
retry 20 3 docker compose exec -T crowdsec \
    cscli decisions add -i "$IP" -d 5m -R smoke-test

wait_for_score "http://127.0.0.1:9102" "$IP" 120
