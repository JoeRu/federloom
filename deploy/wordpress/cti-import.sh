#!/usr/bin/env bash
# Fetches the SwarmGuard CTI blocklist and imports it into the local CrowdSec LAPI.
# Install as a cron job (see below) — run as root on the wordpress host.
#
# Cron (every 15 minutes):
#   */15 * * * * /opt/swarmguard/deploy/wordpress/cti-import.sh >> /var/log/swarmguard-cti.log 2>&1
set -euo pipefail

SWARMGUARD_API="http://127.0.0.1:9102"
CROWDSEC_CTR="crowdsec"
DURATION="168h"
REASON="federloom-reputation"

IPS=$(curl -sf --max-time 10 "${SWARMGUARD_API}/crowdsec/v1/decisions") || {
  echo "[$(date -Iseconds)] WARN: could not reach FederLoom API at ${SWARMGUARD_API}" >&2
  exit 0
}

if [ -z "$IPS" ]; then
  echo "[$(date -Iseconds)] INFO: blocklist empty, nothing to import"
  exit 0
fi

COUNT=$(echo "$IPS" | grep -c .) || COUNT=0
echo "$IPS" | docker exec -i "$CROWDSEC_CTR" \
  cscli decisions import -i - --format values \
  --duration "$DURATION" --reason "$REASON" -o raw 2>&1 \
  | tail -1 \
  | xargs -I{} echo "[$(date -Iseconds)] INFO: imported $COUNT IPs — {}"
