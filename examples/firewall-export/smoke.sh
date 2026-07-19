#!/usr/bin/env bash
# Smoke: the export endpoint answers 200 text/plain (empty list is fine —
# this example has no ingest; it proves the serving path only).
set -euo pipefail
. "$(git rev-parse --show-toplevel)/test/examples/lib.sh"
retry 20 3 curl -fsS -o /dev/null http://127.0.0.1:9102/crowdsec/v1/decisions
ct=$(curl -fsS -o /dev/null -w '%{content_type}' http://127.0.0.1:9102/crowdsec/v1/decisions)
case "$ct" in text/plain*) echo "PASS: export endpoint serves text/plain" ;;
              *) echo "FAIL: content-type $ct"; exit 1 ;; esac
