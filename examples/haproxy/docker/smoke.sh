#!/usr/bin/env bash
set -euo pipefail
. "$(git rev-parse --show-toplevel)/test/examples/lib.sh"
IP=203.0.113.99
retry 20 3 docker compose exec -T crowdsec \
    cscli decisions add -i "$IP" -d 5m -R smoke-test
wait_for_score "http://127.0.0.1:9102" "$IP" 120
# Consume direction: fetch script must land the IP in the ACL file.
./fetch-blocklist.sh
grep -q "^$IP\$" acl/blocklist.acl
echo "PASS: blocklist.acl contains $IP"
# The host file alone doesn't prove HAProxy sees it — a single-file bind
# mount would stay pinned to the pre-refresh inode across the fetch
# script's atomic rename. Assert the running container's own view.
docker compose exec -T haproxy grep -q "^$IP\$" /usr/local/etc/haproxy/acl/blocklist.acl
echo "PASS: haproxy container view of blocklist.acl contains $IP"
git checkout -- acl/blocklist.acl   # restore the committed placeholder
