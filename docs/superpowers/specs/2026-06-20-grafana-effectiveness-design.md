# SwarmGuard Effectiveness Dashboard Design

**Goal:** Add a "SwarmGuard — Effectiveness" Grafana dashboard that shows all three nodes (honeypot, mailcow, wordpress) side-by-side on a metric-first layout, enabling instant comparison of blocking effectiveness, event rates, federation health, and recidivism across the swarm.

---

## Scope

Two types of changes — no Go code:

1. Three new Prometheus datasource YAML files (one per node)
2. One new Grafana dashboard JSON file (`swarmguard-effectiveness.json`)

The existing `swarmguard-dashboard.json` and its SQLite datasource are untouched.

---

## Datasources

Three new files in `deploy/grafana/provisioning/datasources/`:

| File | Name | URL | UID |
|---|---|---|---|
| `prometheus-honeypot.yml` | `Prometheus — Honeypot` | `http://167.233.115.41:9101` | `prom-honeypot` |
| `prometheus-mailcow.yml` | `Prometheus — Mailcow` | `http://100.120.31.14:9101` | `prom-mailcow` |
| `prometheus-wordpress.yml` | `Prometheus — WordPress` | `http://100.92.58.24:9101` | `prom-wordpress` |

Each file follows the same structure:

```yaml
apiVersion: 1
datasources:
  - name: "Prometheus — <Node>"
    type: prometheus
    access: proxy
    uid: prom-<node>
    url: http://<ip>:9101
    editable: false
```

**Network note:** Mailcow (`100.120.31.14`) and WordPress (`100.92.58.24`) are Tailscale IPs. Grafana reaches them via the Docker host's Tailscale interface. The honeypot (`167.233.115.41`) is a public IP reachable directly.

---

## Dashboard

**File:** `deploy/grafana/provisioning/dashboards/swarmguard-effectiveness.json`
**Title:** `SwarmGuard — Effectiveness`
**UID:** `swarmguard-effectiveness`

### Template variable

```json
{
  "name": "block_threshold",
  "type": "constant",
  "label": "Block threshold",
  "query": "80",
  "hide": 0
}
```

Same as the existing dashboard — operator sets this once to match their `reputation.block_threshold` config value.

### Layout

Metric-first: six rows, each with three panels (honeypot | mailcow | wordpress), each panel width=8, fitting the 24-column grid exactly.

```
Row: Blocked IPs
  [stat w=8] Honeypot  [stat w=8] Mailcow  [stat w=8] WordPress

Row: Block rate
  [timeseries w=8] Honeypot  [timeseries w=8] Mailcow  [timeseries w=8] WordPress

Row: Events received
  [timeseries w=8] Honeypot  [timeseries w=8] Mailcow  [timeseries w=8] WordPress

Row: Federation in
  [timeseries w=8] Honeypot  [timeseries w=8] Mailcow  [timeseries w=8] WordPress

Row: Candidates (approaching block threshold)
  [table w=8] Honeypot  [table w=8] Mailcow  [table w=8] WordPress

Row: Recidivism
  [stat w=8] Honeypot  [stat w=8] Mailcow  [stat w=8] WordPress
```

### Panel specifications

#### Row 1 — Blocked IPs

Three stat panels, one per node datasource.

```
Query:   sum(swarmguard_blocked_ips)
Display: last value, color threshold green→red at 1
Title:   "Blocked IPs — <Node>"
```

#### Row 2 — Block rate

Three timeseries panels showing how fast each node is blocking over time.

```
Query:   sum(increase(swarmguard_blocks_total[$__interval]))
Display: bars, 1-minute step
Title:   "Block rate — <Node>"
```

#### Row 3 — Events received

Three timeseries panels showing total ingest event rate (local + federated combined).

```
Query:   sum(rate(swarmguard_events_received_total[$__interval])) * 60
Display: lines, unit: events/min
Title:   "Events/min — <Node>"
```

#### Row 4 — Federation in

Three timeseries panels showing the rate of inbound gossip messages from remote peers. A flat line at zero means federation has stopped flowing to that node.

```
Query:   rate(swarmguard_events_federated_total{direction="in"}[$__interval]) * 60
Display: lines, unit: messages/min
Title:   "Federation in — <Node>"
```

`swarmguard_events_federated_total{direction="in"}` is incremented by the node on each inbound gossip message processed. It is a reliable signal of live federation activity without needing to know the local peer ID.

#### Row 5 — Candidates

Three table panels listing IPs currently above the gauge threshold but below block threshold on each node. Each table is narrow (w=8) so only shows IP and Score columns.

```
Query:   swarmguard_ip_score < $block_threshold
Format:  table, instant: true
Columns: ip → "IP", Value → "Score"
Sort:    Score descending
Title:   "Candidates — <Node>"
```

#### Row 6 — Recidivism

Three stat panels showing the total count of previously-unblocked IPs that were re-blocked within 7 days. High values indicate persistent attackers that keep returning after decaying below threshold.

```
Query:   sum(swarmguard_block_recurrence_total)
Display: last value, no threshold colouring (informational)
Title:   "Recidivism — <Node>"
```

Showing this stat across all three nodes reveals whether the same IPs are recurring on multiple nodes simultaneously — a strong signal of a coordinated, persistent attacker.

---

## Panel ID allocation

Panels in the new dashboard use IDs 1–24 (fresh file, no conflicts with the existing dashboard).

| Row | Honeypot ID | Mailcow ID | WordPress ID |
|---|---|---|---|
| Row header | 1 | — | — |
| Blocked IPs | 2 | 3 | 4 |
| Row header | 5 | — | — |
| Block rate | 6 | 7 | 8 |
| Row header | 9 | — | — |
| Events/min | 10 | 11 | 12 |
| Row header | 13 | — | — |
| Federation in | 14 | 15 | 16 |
| Row header | 17 | — | — |
| Candidates | 18 | 19 | 20 |
| Row header | 21 | — | — |
| Recidivism | 22 | 23 | 24 |

---

## gridPos layout

Each row header: `h=1, w=24, x=0`
Each panel: `h=6 (stat/timeseries rows) or h=8 (table rows), w=8`

```
y=0:   Row header — Blocked IPs
y=1:   Blocked IPs   (h=4): x=0, x=8, x=16
y=5:   Row header — Block rate
y=6:   Block rate    (h=6): x=0, x=8, x=16
y=12:  Row header — Events received
y=13:  Events/min    (h=6): x=0, x=8, x=16
y=19:  Row header — Federation in
y=20:  Federation    (h=6): x=0, x=8, x=16
y=26:  Row header — Candidates
y=27:  Candidates    (h=8): x=0, x=8, x=16
y=35:  Row header — Recidivism
y=36:  Recidivism    (h=4): x=0, x=8, x=16
```

---

## Verification

After provisioning:

```bash
# 1. Restart Grafana to load new datasources and dashboard
docker compose -f /container/compose/grafana/docker-compose.yml restart grafana

# 2. Confirm datasources are reachable (from the host, not container)
curl -sf http://167.233.115.41:9101/metrics | grep swarmguard_blocked_ips
curl -sf http://100.120.31.14:9101/metrics | grep swarmguard_blocked_ips
curl -sf http://100.92.58.24:9101/metrics  | grep swarmguard_blocked_ips

# 3. Open http://grafana.joesnuc:3030 → "SwarmGuard — Effectiveness"
#    Confirm: six rows, three columns, all panels loading data
#    Confirm: mailcow and wordpress blocked IPs > 0 (they have lower thresholds)
#    Confirm: federation timeseries shows activity on mailcow and wordpress
```
