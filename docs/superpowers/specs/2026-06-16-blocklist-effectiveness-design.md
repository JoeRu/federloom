# Blocklist Effectiveness Monitoring — Design Spec

**Date:** 2026-06-16
**Scope:** WordPress node (generalises to any SwarmGuard node)
**Goal:** Measure and expose blocklist effectiveness across three axes — coverage, false-positive risk, and time-to-block latency — with enough per-rule granularity to drive rule tuning decisions.

---

## Problem

SwarmGuard's existing metrics (`swarmguard_rules_fired_total`, `swarmguard_blocked_ips`) tell you *how much* is happening but not *how well* it is working. There is no signal for:

- How many attacker requests reached nginx before the block landed ("slip-through")
- Whether a rule is firing too conservatively (high single-source rate) or too late (high slip-through)
- Whether blocked IPs are returning after auto-unblock (block duration too short)
- How much of the block list is explained by CrowdSec vs. federation alone

---

## Architecture

Three deliverables, each independent but feeding the same label namespace (`rule`):

```
SwarmGuard process          textfile exporter (cron)       CLI report (on-demand)
  ↓ emits at block time       ↓ queries SQLite + nginx        ↓ same queries + richer text
  Prometheus /metrics         node_exporter textfile         stdout
  (real-time, per-rule)       (5-min cadence, cross-system)  (any window, human-readable)
        ↓                           ↓
        └────────────────────────────┘
                  Grafana (future dashboard)
```

---

## Deliverable 1 — Native SwarmGuard Metrics

**Files:** `internal/observability/prometheus.go`, `internal/node/node.go`

### New metrics

| Metric | Type | Labels | Semantics |
|---|---|---|---|
| `swarmguard_blocks_total` | Counter | `rule`, `source` | Incremented on every block decision. `source`: `preemptive` (no prior nginx hit recorded) or `reactive` (IP was seen in nginx log before block). Computed by exporter retroactively — Go emits without `source`; exporter annotates. **Revised:** Go emits `swarmguard_blocks_total{rule}` only; `source` breakdown lives in the textfile exporter which has nginx log access. |
| `swarmguard_time_to_block_seconds` | Histogram | `rule` | Duration from the first event recorded for an IP to the moment it is added to the enforce set. Buckets: 0, 30s, 1m, 2m, 5m, 10m, 30m, 1h, 4h. |
| `swarmguard_corroboration_at_block` | Histogram | `rule` | Number of distinct `reporter_id` values seen for an IP at the moment the block rule fires. Buckets: 1, 2, 3, 4, 5, 10. Reveals rules always firing at `min_corroboration` (possibly too low). |
| `swarmguard_unblocks_total` | Counter | `rule`, `returned` | Incremented on every auto-unblock. `returned`: `true` if the same IP generates a new event within 7 days, `false` otherwise. `returned=true` indicates block duration is too short for that rule's threat profile. |

### Wiring

- `swarmguard_blocks_total` and `swarmguard_time_to_block_seconds` and `swarmguard_corroboration_at_block`: emitted in `node.go` in the `processBlock` path, after a rule match produces an `action: block`.
- `swarmguard_unblocks_total`: emitted in the decay/unblock path in `internal/reputation/` or `internal/node/node.go` when an IP's score drops below `unblock_threshold`. The `returned` label requires a small lookup: when a new event arrives for an IP, check if it was previously unblocked; if so, increment `swarmguard_unblocks_total{returned="true"}` retroactively. Simplest approach: store a `recently_unblocked` in-memory set with a 7-day TTL.

### What these enable for rule tuning

| Observation | Likely diagnosis | Tuning action |
|---|---|---|
| `time_to_block_seconds{rule="ssh-brute-burst"}` P95 > 15m | `burst_window` too wide | Tighten `burst_window` |
| `corroboration_at_block{rule="http-probe-consensus"}` always = 2 | `min_corroboration` is the exact trigger, no headroom | Fine — or lower to 1 if slip-through is high |
| `unblocks_total{rule="score-fallback", returned="true"}` > 20% | Score decays too fast for this rule's attacker profile | Extend `half_life` or raise `block_threshold` |
| `blocks_total{rule="crowdsec-decision"}` >> all others | CrowdSec is doing the heavy lifting | Validate other rules aren't redundant |

---

## Deliverable 2 — Textfile Exporter

**File:** `deploy/wordpress/swarmguard-exporter.sh`

**Runtime:** cron every 5 minutes on the WordPress server, writing to `/var/lib/node_exporter/textfile/swarmguard_effectiveness.prom`. `node_exporter` must be started with `--collector.textfile.directory=/var/lib/node_exporter/textfile/`.

### Metrics emitted

```
# HELP swarmguard_nginx_slip_through_total Nginx requests served to IPs in the window before their block landed, by rule.
# TYPE swarmguard_nginx_slip_through_total gauge
swarmguard_nginx_slip_through_total{rule="http-probe-consensus"} 4

# HELP swarmguard_blocks_preemptive_total Blocks where the IP had zero nginx hits before block (federation caught it first).
# TYPE swarmguard_blocks_preemptive_total gauge
swarmguard_blocks_preemptive_total{rule="score-fallback"} 2

# HELP swarmguard_blocks_single_source_total Blocks where only one reporter corroborated at block time (higher false-positive risk).
# TYPE swarmguard_blocks_single_source_total gauge
swarmguard_blocks_single_source_total{rule="http-probe-consensus"} 2

# HELP swarmguard_block_recurrence_ratio Fraction of auto-unblocked IPs (per rule) that re-appeared within 7 days.
# TYPE swarmguard_block_recurrence_ratio gauge
swarmguard_block_recurrence_ratio{rule="ssh-brute-burst"} 0.25

# HELP swarmguard_crowdsec_overlap_ratio Fraction of SwarmGuard-blocked IPs also present in CrowdSec decisions.
# TYPE swarmguard_crowdsec_overlap_ratio gauge
swarmguard_crowdsec_overlap_ratio 0.79

# HELP swarmguard_crowdsec_only_total IPs CrowdSec banned that SwarmGuard did not block (federation gap).
# TYPE swarmguard_crowdsec_only_total gauge
swarmguard_crowdsec_only_total 8

# HELP swarmguard_exporter_last_run_timestamp_seconds Unix timestamp of the last successful exporter run.
# TYPE swarmguard_exporter_last_run_timestamp_seconds gauge
swarmguard_exporter_last_run_timestamp_seconds 1781620800
```

### Implementation notes

- **Nginx log access:** `docker exec wordpress_docker_stack-nginx_webmail-1 cat /var/log/nginx/access.log`
- **Slip-through computation:** extract source IPs from nginx log entries within the last 5-minute window → join against `blocks` table in SQLite (WHERE `blocked_at` > first nginx hit for that IP) → count requests that arrived before block.
- **Per-rule slip-through:** join via `rule_firings` table to get which rule fired for each blocked IP.
- **Single-source:** query `events` table for each block: `COUNT(DISTINCT reporter) WHERE ip = ? AND ts <= blocks.blocked_at`.
- **CrowdSec overlap:** `docker exec crowdsec cscli decisions list -o json` → extract IPs → compare with `SELECT ip FROM blocks WHERE unblocked_at IS NULL`.
- **Window:** exporter always looks at a rolling 24h window for rate-style metrics. The `last_run_timestamp_seconds` lets Grafana detect a stalled exporter.
- **Atomicity:** write to a `.tmp` file first, then `mv` to the final `.prom` path to avoid node_exporter reading a partial file.

---

## Deliverable 3 — CLI Effectiveness Report

**File:** `deploy/wordpress/effectiveness-report.sh`

**Usage:**
```bash
./effectiveness-report.sh              # default: last 24h
./effectiveness-report.sh --hours 6
./effectiveness-report.sh --days 7
./effectiveness-report.sh --since 2026-06-10
```

### Output format

```
=== SwarmGuard Effectiveness Report ===
Node: wordpress  |  Window: 2026-06-15 14:00 → 2026-06-16 14:00 (24h)

── Coverage ──────────────────────────────────────────────────
IPs blocked in window:               47
  preemptive (no prior nginx hit):   16  (34%)
  reactive (nginx hit before block): 31  (66%)
Nginx requests from reactive IPs:   128   (requests served before block landed)

── Time-to-Block Latency ─────────────────────────────────────
Median:  4m 23s    P95: 18m 12s    Fastest: 0s (preemptive)

── False Positive Risk ───────────────────────────────────────
Single-source blocks:                 5 IPs
Auto-unblocked in window:             8 IPs
  returned after unblock:             2  (25%)
  clean exits:                        6  (75%)

── CrowdSec Insights ─────────────────────────────────────────
CrowdSec decisions in window:        39
  overlap with SwarmGuard:           31  (79%)
  CrowdSec-only (SwarmGuard missed):  8
  SwarmGuard-only (federation extra): 16

Top CrowdSec scenarios:
  crowdsecurity/http-crawl-non_statics   18
  crowdsecurity/wordpress-scan           12
  crowdsecurity/http-sensitive-files      7

Top countries:  CN: 14  RU: 9  US: 6  DE: 4

── Rule Breakdown ────────────────────────────────────────────
Rule                        Fires  Slip-through  Single-src  Returned
crowdsec-decision               12     0  (0%)       0          1
http-probe-consensus             9     4 (44%)       2          0
ssh-brute-burst                  5     0  (0%)       0          0
honeypot-shell-exec              3     0  (0%)       0          0
score-fallback                   3     3 (100%)      1          0

── Active Blocklist ──────────────────────────────────────────
Currently blocked:    23 IPs
Oldest active block:  2026-06-14 09:12
```

### Implementation notes

- **Dependencies:** `sqlite3`, `awk`, `docker`, `jq` (for CrowdSec JSON). All present on the WordPress server.
- **SQLite path:** `/var/lib/swarmguard/metrics.db` (mounted from the `swarmguard-data` volume).
- **Window filter:** convert `--since`/`--hours`/`--days` to a Unix epoch cutoff; pass as a `WHERE ts >= $cutoff` bind parameter to SQLite.
- **Latency:** for each IP in `blocks` WHERE `blocked_at >= cutoff`, compute `blocked_at - MIN(events.ts WHERE ip = ? AND ts <= blocked_at)`.
- **Preemptive detection:** an IP is `preemptive` if it has zero rows in the parsed nginx log for its IP before `blocks.blocked_at`.
- **Rule column in breakdown:** join `rule_firings` on IP + closest `ts <= blocked_at` to get the winning rule.
- **CrowdSec JSON:** `cscli decisions list -o json --since <window>` returns structured data with `scenario`, `value` (IP), `country`, `as_name`.
- **No root required** if the script runs as the same user that owns the SwarmGuard volume and has access to `docker exec`.

---

## Data flow summary

```
nginx access log ──┐
                   ├──► effectiveness-report.sh   (on-demand)
SwarmGuard SQLite ─┤
                   └──► swarmguard-exporter.sh    (cron 5min) ──► node_exporter ──► Prometheus ──► Grafana
CrowdSec LAPI ─────┘

SwarmGuard process ────────────────────────────────────────────► /metrics        ──► Prometheus ──► Grafana
  (new: blocks_total, time_to_block_seconds,
        corroboration_at_block, unblocks_total)
```

---

## Files changed / created

| Path | Action |
|---|---|
| `internal/observability/prometheus.go` | Add 4 new metric definitions |
| `internal/node/node.go` | Emit new metrics at block/unblock decision points |
| `deploy/wordpress/swarmguard-exporter.sh` | New — textfile exporter cron script |
| `deploy/wordpress/effectiveness-report.sh` | New — CLI on-demand report |

The exporter and report scripts are WordPress-specific but designed so they can be copied to any node with minimal path changes (SQLite path, nginx container name).

---

## Out of scope

- Grafana dashboard JSON (follow-up, after metrics are flowing)
- Alerting rules (future, once baselines are established)
- Generalising to mailcow/honeypot nodes (straightforward copy, different nginx container name and purpose filter)
