#!/usr/bin/env bash
# Detects "local truth" for the LOCAL-ONLY whitelist (spec §6.2):
# own public IP(s), gateways, configured DNS, local Docker ranges, RFC1918.
#
# SECURITY: this writes the whitelist. A wrong entry that whitelists a public
# range is a real security hole. Therefore:
#   - be CONSERVATIVE (when in doubt, do NOT whitelist),
#   - PRINT findings and require explicit confirmation before writing,
#   - mark every entry scope=local-only (NEVER federated).
set -euo pipefail

echo "# Detected local truth (review before accepting) — scope: local-only"

echo "## Loopback / RFC1918"
echo "127.0.0.0/8"; echo "::1/128"
echo "10.0.0.0/8"; echo "172.16.0.0/12"; echo "192.168.0.0/16"

echo "## Default gateway(s)"
ip route 2>/dev/null | awk '/default/ {print $3}' | sort -u || true

echo "## Configured DNS"
{ grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}'; } | sort -u || true

echo "## Local interface addresses"
ip -o addr show 2>/dev/null | awk '{print $4}' | sort -u || true

echo "## Docker bridge ranges (if docker present)"
if command -v docker >/dev/null 2>&1; then
  docker network inspect $(docker network ls -q) 2>/dev/null \
    | grep -Eo '"Subnet": "[^"]+"' | awk -F'"' '{print $4}' | sort -u || true
fi

echo
echo "NOTE: public interface addresses are listed for review but NOT auto-accepted."
echo "Confirm each entry; nothing is written without your explicit 'yes'."
