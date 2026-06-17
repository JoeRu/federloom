#!/usr/bin/env bash
# swarmguard-exporter.sh — textfile exporter for node_exporter (5-min cron)
# Queries SwarmGuard SQLite + CrowdSec and writes effectiveness metrics.
set -euo pipefail
export PATH="/run/current-system/sw/bin:/root/.nix-profile/bin:/usr/local/bin:/usr/bin:/bin"

SQLITE_DB="/var/lib/docker/volumes/wordpress_swarmguard-data/_data/metrics.db"
NGINX_CTR="wordpress_docker_stack-nginx_webmail-1"
CROWDSEC_CTR="crowdsec"
OUTDIR="/var/lib/node_exporter/textfile"
OUTFILE="$OUTDIR/swarmguard_effectiveness.prom"
TMPFILE="$OUTFILE.tmp"
WINDOW_HOURS=24

SINCE=$(date -d "$WINDOW_HOURS hours ago" +%s)

mkdir -p "$OUTDIR"

# Abort cleanly if DB doesn't exist yet.
if [[ ! -f "$SQLITE_DB" ]]; then
  echo "# swarmguard_exporter: metrics.db not found at $SQLITE_DB" > "$TMPFILE"
  mv "$TMPFILE" "$OUTFILE"
  exit 0
fi

q() { sqlite3 "$SQLITE_DB" "$1"; }

# ── Single-source blocks per rule (corroboration = 1 at block time) ──────────
# For each block in window, count distinct reporters in events up to blocked_at.
# A block is "single-source" if only 1 reporter corroborated before block.
single_source=$(q "
  SELECT COALESCE(rf.rule, 'unknown'), COUNT(*)
  FROM blocks b
  LEFT JOIN (
      SELECT ip, rule, MIN(ts) AS fire_ts
      FROM rule_firings WHERE action='block'
      GROUP BY ip
  ) rf ON rf.ip = b.ip
  WHERE b.blocked_at >= $SINCE
    AND (
      SELECT COUNT(DISTINCT reporter) FROM events e
      WHERE e.ip = b.ip AND e.ts <= b.blocked_at
    ) = 1
  GROUP BY rf.rule;
" | awk -F'|' '{print "swarmguard_blocks_single_source_total{rule=\""$1"\"} "$2}') || single_source=""

# ── Slip-through: nginx IPs that are also in the block list ──────────────────
# Approximate: intersection of nginx source IPs and currently-blocked IPs.
# Note: nginx access.log is a symlink to /dev/stdout, so use docker logs instead.
nginx_ips=$(docker logs "$NGINX_CTR" --since "${WINDOW_HOURS}h" 2>/dev/null \
  | awk '{print $1}' \
  | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$|^[0-9a-f:]+$' \
  | sort -u) || nginx_ips=""

blocked_ips=$(q "SELECT DISTINCT ip FROM blocks WHERE blocked_at >= $SINCE AND unblocked_at IS NULL;" | sort) || blocked_ips=""

if [[ -n "$nginx_ips" && -n "$blocked_ips" ]]; then
  slip_count=$(comm -12 <(echo "$nginx_ips") <(echo "$blocked_ips") | wc -l | tr -d ' ')
else
  slip_count=0
fi

# Per-rule slip-through (blocked IPs that also appear in nginx log)
slip_by_rule=""
if [[ -n "$nginx_ips" ]]; then
  slip_by_rule=$(q "
    SELECT COALESCE(rf.rule, 'unknown'), COUNT(*)
    FROM blocks b
    LEFT JOIN (
        SELECT ip, rule, MIN(ts) AS fire_ts
        FROM rule_firings WHERE action='block'
        GROUP BY ip
    ) rf ON rf.ip = b.ip
    WHERE b.blocked_at >= $SINCE
      AND b.unblocked_at IS NULL
      AND b.ip IN ($(echo "$nginx_ips" | awk '{printf "\"%s\",",$0}' | sed 's/,$//'))
    GROUP BY rf.rule;
  " 2>/dev/null | awk -F'|' '{print "swarmguard_nginx_slip_through_total{rule=\""$1"\"} "$2}') || slip_by_rule=""
fi

# ── Recurrence ratio per rule ─────────────────────────────────────────────────
# Fraction of IPs unblocked in window that were re-blocked within 7 days.
seven_days_ago=$(date -d "7 days ago" +%s)
recurrence=$(q "
  SELECT
    COALESCE(rf.rule, 'unknown') AS rule,
    COUNT(*) AS unblocked,
    SUM(CASE WHEN EXISTS (
      SELECT 1 FROM blocks b2
      WHERE b2.ip = b.ip AND b2.blocked_at > b.unblocked_at
    ) THEN 1 ELSE 0 END) AS returned
  FROM blocks b
  LEFT JOIN (
      SELECT ip, rule, MIN(ts) AS fire_ts
      FROM rule_firings WHERE action='block'
      GROUP BY ip
  ) rf ON rf.ip = b.ip
  WHERE b.unblocked_at >= $seven_days_ago AND b.unblocked_at IS NOT NULL
  GROUP BY rf.rule;
" | awk -F'|' '{
    ratio = ($2 > 0) ? $3/$2 : 0
    print "swarmguard_block_recurrence_ratio{rule=\""$1"\"} "ratio
}') || recurrence=""

# ── CrowdSec overlap ──────────────────────────────────────────────────────────
cs_decisions=$(docker exec "$CROWDSEC_CTR" \
  cscli decisions list -o json --since "${WINDOW_HOURS}h" 2>/dev/null \
  | jq -r '.[].value // empty' 2>/dev/null | sort -u) || cs_decisions=""

swarm_blocked=$(q "SELECT DISTINCT ip FROM blocks WHERE blocked_at >= $SINCE AND unblocked_at IS NULL;" | sort) || swarm_blocked=""

if [[ -n "$cs_decisions" && -n "$swarm_blocked" ]]; then
  cs_count=$(echo "$cs_decisions" | wc -l | tr -d ' ')
  overlap=$(comm -12 <(echo "$cs_decisions") <(echo "$swarm_blocked") | wc -l | tr -d ' ')
  cs_only=$(comm -23 <(echo "$cs_decisions") <(echo "$swarm_blocked") | wc -l | tr -d ' ')
  overlap_ratio=$(awk "BEGIN{printf \"%.4f\", ($cs_count > 0) ? $overlap/$cs_count : 0}")
else
  cs_count=0; overlap=0; cs_only=0; overlap_ratio=0
fi

# ── Write output atomically ───────────────────────────────────────────────────
cat > "$TMPFILE" << EOF
# HELP swarmguard_blocks_single_source_total Blocks with only 1 corroborating reporter (higher false-positive risk), by rule.
# TYPE swarmguard_blocks_single_source_total gauge
${single_source}
# HELP swarmguard_nginx_slip_through_total Blocked IPs that also appear in nginx access log (approximate slip-through), by rule.
# TYPE swarmguard_nginx_slip_through_total gauge
${slip_by_rule}
# HELP swarmguard_nginx_slip_through_total_all Total blocked IPs appearing in nginx log (all rules).
# TYPE swarmguard_nginx_slip_through_total_all gauge
swarmguard_nginx_slip_through_total_all ${slip_count}
# HELP swarmguard_block_recurrence_ratio Fraction of auto-unblocked IPs re-blocked within 7 days, by rule.
# TYPE swarmguard_block_recurrence_ratio gauge
${recurrence}
# HELP swarmguard_crowdsec_overlap_ratio Fraction of CrowdSec decisions also present in SwarmGuard block list.
# TYPE swarmguard_crowdsec_overlap_ratio gauge
swarmguard_crowdsec_overlap_ratio ${overlap_ratio}
# HELP swarmguard_crowdsec_only_total IPs banned by CrowdSec but not in SwarmGuard block list.
# TYPE swarmguard_crowdsec_only_total gauge
swarmguard_crowdsec_only_total ${cs_only}
# HELP swarmguard_exporter_last_run_timestamp_seconds Unix timestamp of last successful exporter run.
# TYPE swarmguard_exporter_last_run_timestamp_seconds gauge
swarmguard_exporter_last_run_timestamp_seconds $(date +%s)
EOF

mv "$TMPFILE" "$OUTFILE"
