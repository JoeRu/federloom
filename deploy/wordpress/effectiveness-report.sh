#!/usr/bin/env bash
# effectiveness-report.sh — on-demand SwarmGuard effectiveness report
# Run directly on the WordPress server.
# Usage: ./effectiveness-report.sh [--hours N | --days N | --since YYYY-MM-DD]
set -euo pipefail
export PATH="/run/current-system/sw/bin:/root/.nix-profile/bin:/usr/local/bin:/usr/bin:/bin"

SQLITE_DB="/var/lib/docker/volumes/wordpress_federloom-data/_data/metrics.db"
NGINX_CTR="wordpress_docker_stack-nginx_webmail-1"
CROWDSEC_CTR="crowdsec"

# ── Parse arguments ───────────────────────────────────────────────────────────
SINCE_EPOCH=""
WINDOW_LABEL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hours)
      [[ "${2:-}" =~ ^[0-9]+$ ]] || { echo "ERROR: --hours requires a positive integer" >&2; exit 1; }
      SINCE_EPOCH=$(date -d "$2 hours ago" +%s)
      WINDOW_LABEL="last ${2}h"
      shift 2 ;;
    --days)
      [[ "${2:-}" =~ ^[0-9]+$ ]] || { echo "ERROR: --days requires a positive integer" >&2; exit 1; }
      SINCE_EPOCH=$(date -d "$2 days ago" +%s)
      WINDOW_LABEL="last ${2}d"
      shift 2 ;;
    --since)
      SINCE_EPOCH=$(date -d "$2" +%s)
      WINDOW_LABEL="since $2"
      shift 2 ;;
    *)
      echo "Usage: $0 [--hours N | --days N | --since YYYY-MM-DD]" >&2
      exit 1 ;;
  esac
done

if [[ -z "$SINCE_EPOCH" ]]; then
  SINCE_EPOCH=$(date -d "24 hours ago" +%s)
  WINDOW_LABEL="last 24h"
fi

NOW=$(date +%s)
SINCE_HR=$(date -d "@$SINCE_EPOCH" '+%Y-%m-%d %H:%M')
NOW_HR=$(date -d "@$NOW" '+%Y-%m-%d %H:%M')

if [[ ! -f "$SQLITE_DB" ]]; then
  echo "ERROR: metrics.db not found at $SQLITE_DB" >&2
  echo "Enable observability.sqlite_path in deploy/wordpress/config.yaml and redeploy." >&2
  exit 1
fi

q() { sqlite3 "$SQLITE_DB" "$1"; }

echo "=== FederLoom Effectiveness Report ==="
echo "Node: wordpress  |  Window: $SINCE_HR → $NOW_HR ($WINDOW_LABEL)"
echo ""

# ── Coverage ──────────────────────────────────────────────────────────────────
total_blocked=$(q "SELECT COUNT(DISTINCT ip) FROM blocks WHERE blocked_at >= $SINCE_EPOCH;") || total_blocked=0

# Get nginx access log IPs with parsed timestamps
nginx_log=$(docker logs "$NGINX_CTR" --since "$((NOW - SINCE_EPOCH))s" 2>/dev/null) || nginx_log=""

# Build temp file: ip<TAB>epoch_ts from nginx log
NGINX_TMP=$(mktemp)
trap 'rm -f "$NGINX_TMP"' EXIT
if [[ -n "$nginx_log" ]]; then
  printf '%s\n' "$nginx_log" | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}[[:space:]]' | awk '
  BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m)
    for (i=1;i<=12;i++) month[m[i]]=i
  }
  {
    ip=$1
    # field 4: [16/Jun/2026:14:29:12
    split(substr($4,2), dt, /[:/]/)
    # dt[1]=day, dt[2]=month_abbr, dt[3]=year, dt[4]=hh, dt[5]=mm, dt[6]=ss
    mo = month[dt[2]]
    if (mo == "") next
    epoch = mktime(dt[3]" "mo" "dt[1]" "dt[4]" "dt[5]" "dt[6])
    if (epoch > 0) print ip"\t"epoch
  }' > "$NGINX_TMP"
fi

# For each blocked IP in window, check if it had nginx hits before blocked_at
preemptive=0
reactive=0
nginx_requests_before_block=0

if [[ -n "$total_blocked" && "$total_blocked" -gt 0 ]]; then
  while IFS='|' read -r ip blocked_at; do
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || continue
    [[ "$blocked_at" =~ ^[0-9]+$ ]] || continue
    req_before=$(awk -v ip="$ip" -v bt="$blocked_at" -v since="$SINCE_EPOCH" \
      'BEGIN{c=0} $1==ip && $2>=since && $2<bt {c++} END{print c}' "$NGINX_TMP")
    if [[ "$req_before" -eq 0 ]]; then
      ((preemptive++)) || true
    else
      ((reactive++)) || true
      ((nginx_requests_before_block+=req_before)) || true
    fi
  done < <(q "SELECT ip, blocked_at FROM blocks WHERE blocked_at >= $SINCE_EPOCH;" || true)
fi

echo "── Coverage ──────────────────────────────────────────────────────────────────"
printf "IPs blocked in window:               %d\n" "$total_blocked"
if [[ "$total_blocked" -gt 0 ]]; then
  printf "  preemptive (no prior nginx hit):   %d  (%d%%)\n" \
    "$preemptive" "$((preemptive*100/total_blocked))"
  printf "  reactive (nginx hit before block): %d  (%d%%)\n" \
    "$reactive" "$((reactive*100/total_blocked))"
fi
printf "Nginx requests from reactive IPs:    %d   (requests served before block landed)\n" "$nginx_requests_before_block"
echo ""

# ── Time-to-Block Latency ─────────────────────────────────────────────────────
latencies=$(q "
  SELECT b.blocked_at - MIN(e.ts)
  FROM blocks b
  JOIN events e ON e.ip = b.ip AND e.ts <= b.blocked_at
  WHERE b.blocked_at >= $SINCE_EPOCH
  GROUP BY b.ip, b.blocked_at
  ORDER BY 1;
") || latencies=""

if [[ -n "$latencies" ]]; then
  read -r median p95 fastest <<< "$(printf '%s\n' "$latencies" | awk '
  {a[NR]=$1}
  END{
    n=NR
    med=a[int((n+1)/2)]
    p95=a[int(n*0.95+0.5)]
    if (p95 < 1) p95 = a[1]
    fast=a[1]
    printf "%d %d %d\n", med, p95, fast
  }')"
  fmt_sec() {
    local s=$1
    if [[ $s -lt 60 ]]; then echo "${s}s"
    elif [[ $s -lt 3600 ]]; then printf "%dm %ds" $((s/60)) $((s%60))
    else printf "%dh %dm" $((s/3600)) $(((s%3600)/60))
    fi
  }
  echo "── Time-to-Block Latency ─────────────────────────────────────────────────────"
  printf "Median: %s    P95: %s    Fastest: %s (preemptive)\n" \
    "$(fmt_sec $median)" "$(fmt_sec $p95)" "$(fmt_sec $fastest)"
else
  echo "── Time-to-Block Latency ─────────────────────────────────────────────────────"
  echo "No blocks with recorded events in window."
fi
echo ""

# ── False Positive Risk ───────────────────────────────────────────────────────
single_source=$(q "
  SELECT COUNT(DISTINCT b.ip)
  FROM blocks b
  WHERE b.blocked_at >= $SINCE_EPOCH
    AND (SELECT COUNT(DISTINCT reporter) FROM events e
         WHERE e.ip=b.ip AND e.ts<=b.blocked_at) = 1;
") || single_source=0

auto_unblocked=$(q "
  SELECT COUNT(*) FROM blocks
  WHERE blocked_at >= $SINCE_EPOCH AND unblocked_at IS NOT NULL;
") || auto_unblocked=0

returned=$(q "
  SELECT COUNT(*) FROM blocks b
  WHERE b.blocked_at >= $SINCE_EPOCH
    AND b.unblocked_at IS NOT NULL
    AND EXISTS (
      SELECT 1 FROM blocks b2
      WHERE b2.ip=b.ip AND b2.blocked_at > b.unblocked_at
    );
") || returned=0

echo "── False Positive Risk ───────────────────────────────────────────────────────"
printf "Single-source blocks (1 reporter):   %s IPs\n" "$single_source"
printf "Auto-unblocked in window:             %s IPs\n" "$auto_unblocked"
if [[ "$auto_unblocked" -gt 0 ]]; then
  clean=$((auto_unblocked-returned))
  printf "  returned after unblock:             %s  (%d%%)\n" \
    "$returned" "$((returned*100/auto_unblocked))"
  printf "  clean exits:                        %s  (%d%%)\n" \
    "$clean" "$((clean*100/auto_unblocked))"
fi
echo ""

# ── CrowdSec Insights ─────────────────────────────────────────────────────────
cs_since_hours=$(( (NOW - SINCE_EPOCH) / 3600 ))
cs_json=$(docker exec "$CROWDSEC_CTR" \
  cscli decisions list -o json --since "${cs_since_hours}h" 2>/dev/null) || cs_json="[]"

cs_ips=$(echo "$cs_json" | jq -r '.[].value // empty' 2>/dev/null | sort -u) || cs_ips=""
swarm_ips=$(q "SELECT DISTINCT ip FROM blocks WHERE blocked_at >= $SINCE_EPOCH AND unblocked_at IS NULL;" | sort) || swarm_ips=""

cs_count=$(printf '%s' "$cs_ips" | grep -c . || true)
overlap=0; cs_only=0; swarm_only=0
if [[ -n "$cs_ips" && -n "$swarm_ips" ]]; then
  overlap=$(comm -12 <(echo "$cs_ips") <(echo "$swarm_ips") | wc -l | tr -d ' ')
  cs_only=$(comm -23 <(echo "$cs_ips") <(echo "$swarm_ips") | wc -l | tr -d ' ')
  swarm_only=$(comm -13 <(echo "$cs_ips") <(echo "$swarm_ips") | wc -l | tr -d ' ')
fi

echo "── CrowdSec Insights ─────────────────────────────────────────────────────────"
printf "CrowdSec decisions in window:        %d\n" "$cs_count"
if [[ "$cs_count" -gt 0 ]]; then
  printf "  overlap with SwarmGuard:           %d  (%d%%)\n" \
    "$overlap" "$((cs_count>0 ? overlap*100/cs_count : 0))"
  printf "  CrowdSec-only (SwarmGuard missed): %d\n" "$cs_only"
  printf "  SwarmGuard-only (federation extra): %d\n" "$swarm_only"
fi

echo ""
echo "Top CrowdSec scenarios:"
echo "$cs_json" | jq -r '.[].scenario // empty' 2>/dev/null | sort | uniq -c | sort -rn | head -5 \
  | awk '{printf "  %-42s %d\n", $2, $1}' || true

echo ""
echo "Top countries:"
echo "$cs_json" | jq -r '.[].country // empty' 2>/dev/null | sort | uniq -c | sort -rn | head -5 \
  | awk '{printf "  %s: %d  ", $2, $1}' && echo "" || true
echo ""

# ── Rule Breakdown ────────────────────────────────────────────────────────────
echo "── Rule Breakdown ────────────────────────────────────────────────────────────"
printf "%-32s %6s  %14s  %10s  %8s\n" "Rule" "Fires" "Slip-through" "Single-src" "Returned"

q "
  SELECT rf.rule, COUNT(DISTINCT b.ip)
  FROM blocks b
  JOIN (SELECT ip, rule, MIN(ts) AS fire_ts FROM rule_firings WHERE action='block' GROUP BY ip) rf
    ON rf.ip = b.ip
  WHERE b.blocked_at >= $SINCE_EPOCH
  GROUP BY rf.rule
  ORDER BY COUNT(DISTINCT b.ip) DESC;
" 2>/dev/null | while IFS='|' read -r rule fires; do
  rule_esc="${rule//\'/\'\'}"

  # Count IPs for this rule that had at least one nginx hit before their block_at
  slip_ips=0
  while IFS='|' read -r ip blocked_at; do
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || continue
    [[ "$blocked_at" =~ ^[0-9]+$ ]] || continue
    has_hit=$(awk -v ip="$ip" -v bt="$blocked_at" -v since="$SINCE_EPOCH" \
      'BEGIN{c=0} $1==ip && $2>=since && $2<bt {c=1; exit} END{print c}' "$NGINX_TMP")
    [[ "$has_hit" -gt 0 ]] && ((slip_ips++)) || true
  done < <(q "
    SELECT b.ip, b.blocked_at FROM blocks b
    JOIN (SELECT ip, rule FROM rule_firings WHERE action='block' GROUP BY ip) rf
      ON rf.ip=b.ip AND rf.rule='$rule_esc'
    WHERE b.blocked_at >= $SINCE_EPOCH;
  " 2>/dev/null || true)
  slip_pct=0
  [[ "$fires" -gt 0 ]] && slip_pct=$((slip_ips*100/fires)) || true
  slip_fmt="${slip_ips} (${slip_pct}%)"

  ss=$(q "
    SELECT COUNT(DISTINCT b.ip)
    FROM blocks b
    JOIN (SELECT ip, rule, MIN(ts) AS fire_ts FROM rule_firings WHERE action='block' GROUP BY ip) rf
      ON rf.ip = b.ip AND rf.rule='$rule_esc'
    WHERE b.blocked_at >= $SINCE_EPOCH
      AND (SELECT COUNT(DISTINCT reporter) FROM events e
           WHERE e.ip=b.ip AND e.ts<=b.blocked_at) = 1;
  " 2>/dev/null) || ss=0
  ret=$(q "
    SELECT COUNT(*) FROM blocks b
    JOIN (SELECT ip, rule FROM rule_firings WHERE action='block' GROUP BY ip) rf
      ON rf.ip=b.ip AND rf.rule='$rule_esc'
    WHERE b.blocked_at >= $SINCE_EPOCH
      AND b.unblocked_at IS NOT NULL
      AND EXISTS(SELECT 1 FROM blocks b2 WHERE b2.ip=b.ip AND b2.blocked_at>b.unblocked_at);
  " 2>/dev/null) || ret=0
  printf "%-32s %6d  %14s  %10s  %8s\n" "$rule" "$fires" "$slip_fmt" "$ss" "$ret"
done
rm -f "$NGINX_TMP"
echo ""

# ── Active Blocklist ──────────────────────────────────────────────────────────
current=$(q "SELECT COUNT(*) FROM blocks WHERE unblocked_at IS NULL;") || current=0
oldest=$(q "SELECT MIN(datetime(blocked_at,'unixepoch')) FROM blocks WHERE unblocked_at IS NULL;") || oldest="none"
echo "── Active Blocklist ──────────────────────────────────────────────────────────"
printf "Currently blocked:   %s IPs\n" "$current"
printf "Oldest active block: %s\n" "$oldest"
