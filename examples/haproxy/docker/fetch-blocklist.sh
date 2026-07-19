#!/usr/bin/env bash
# Refresh HAProxy's deny list from FederLoom and hot-reload HAProxy.
# Run periodically, e.g. */5 cron:  cd <this dir> && ./fetch-blocklist.sh
set -euo pipefail
cd "$(dirname "$0")"
curl -fsS http://127.0.0.1:9102/crowdsec/v1/decisions > acl/blocklist.acl.tmp
mv acl/blocklist.acl.tmp acl/blocklist.acl
docker compose kill -s HUP haproxy
