# Grafana Dashboard v2 — Peer Topology, Blocklist, Candidates

**Goal:** Add three pieces of information to the existing FederLoom Grafana dashboard — which peers are active (by peer ID + event count), a live count and list of blocked IPs (already present, no changes needed), and a table of IPs approaching the block threshold but not yet blocked.

**No Go changes.** All three features use metrics that already exist. The only files that change are the Grafana dashboard JSON and a dashboard variable.

---

## Scope

Three additions to `deploy/grafana/provisioning/dashboards/federloom-dashboard.json`:

1. A `block_threshold` template variable (constant, user-editable)
2. A "Connected peers" table panel (Prometheus)
3. A "Blocklist candidates" table panel (Prometheus)

The existing "Blocked IPs" stat and "Active blocks + due-time" SQLite table panels are unchanged — they already cover the active blocklist.

---

## Changes

### 1. Template variable: `block_threshold`

```json
{
  "name": "block_threshold",
  "type": "constant",
  "label": "Block threshold",
  "query": "80",
  "hide": 0
}
```

Added to the dashboard's `templating.list` array. Operator sets this once to match their `reputation.block_threshold` config value. It drives the candidates panel filter.

### 2. Panel: Connected peers

Placed in the existing "Live — Prometheus" row, after the "Federation peers" stat.

```
Title:      Connected peers
Type:       table
Datasource: Prometheus
Query:      sum by (reporter_id) (increase(federloom_events_received_total[$__range]))
Columns:    reporter_id → "Peer ID" | Value → "Events"
Sort:       Events descending
```

Uses the existing `reporter_id` label on `federloom_events_received_total`. Shows each peer that sent at least one event during the selected time range, with total event count. Peers connected but silent (no events forwarded) are not shown — acceptable trade-off without adding a new per-peer gauge.

### 3. Panel: Blocklist candidates

Placed in the existing "Live — Prometheus" row, after the "Connected peers" table.

```
Title:      Blocklist candidates
Type:       table
Datasource: Prometheus
Query:      federloom_ip_score < $block_threshold
Columns:    ip → "IP" | Value → "Score"
Sort:       Score descending
```

`federloom_ip_score` already only tracks IPs at or above `score_gauge_threshold` (default: `block_threshold / 2`). Filtering `< $block_threshold` excludes IPs that have already crossed into the block set. The result is precisely the "watching" population — IPs with meaningful scores that have not yet triggered a block decision.

---

## Layout after changes

```
Row: Live — Prometheus
  [timeseries] Events / min by reason
  [timeseries] Rule firings / min by action
  [stat]       Blocked IPs                    ← unchanged
  [stat]       Federation peers               ← unchanged
  [barchart]   Top 10 reporters               ← unchanged
  [table]      Connected peers                ← NEW
  [table]      Blocklist candidates           ← NEW

Row: History — SQLite (local node only)
  [table]  Event log (latest 200)             ← unchanged
  [table]  Active blocks + due-time           ← unchanged
  [table]  Rule firings (latest 200)          ← unchanged
```

---

## Data flow

```
Prometheus (/metrics on :9101)
  federloom_events_received_total{reason, reporter_id}
    → sum by(reporter_id) → Connected peers table

  federloom_ip_score{ip}
    → filter < $block_threshold → Blocklist candidates table

SQLite (metrics.db, unchanged)
  blocks WHERE unblocked_at IS NULL → Active blocks table (existing)
```

---

## Verification

After updating the dashboard JSON:

```bash
# 1. Reload Grafana provisioning (or restart Grafana)
docker compose -f /container/compose/grafana/docker-compose.yml restart grafana

# 2. Open the FederLoom dashboard in a browser

# 3. Connected peers: generate some events, confirm peer IDs appear in table
#    (or check against existing reporter_id values in Prometheus)
curl -s http://localhost:9101/metrics | grep federloom_events_received_total

# 4. Blocklist candidates: confirm IPs with score between threshold/2 and threshold appear
curl -s http://localhost:9101/metrics | grep federloom_ip_score

# 5. Set block_threshold variable to match config value, confirm candidates filter correctly
```
