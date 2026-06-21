# Grafana Effectiveness Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "SwarmGuard — Effectiveness" Grafana dashboard showing all three nodes (honeypot, mailcow, wordpress) side-by-side across six metric rows, plus the three Prometheus datasource files that back it.

**Architecture:** Two types of files — three Prometheus datasource YAMLs (one per node) and one dashboard JSON with 24 panels + 6 row headers. The dashboard JSON is generated via a Python script to avoid error-prone manual authoring of 24 nearly-identical panels. No Go code changes.

**Tech Stack:** Grafana provisioning YAML, Grafana dashboard JSON, Python 3 for generation + validation.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `deploy/grafana/provisioning/datasources/prometheus-honeypot.yml` | Create | Prometheus datasource for honeypot node |
| `deploy/grafana/provisioning/datasources/prometheus-mailcow.yml` | Create | Prometheus datasource for mailcow node |
| `deploy/grafana/provisioning/datasources/prometheus-wordpress.yml` | Create | Prometheus datasource for wordpress node |
| `deploy/grafana/provisioning/dashboards/swarmguard-effectiveness.json` | Create | Effectiveness dashboard JSON |

---

## Task 1: Prometheus datasource YAML files

**Files:**
- Create: `deploy/grafana/provisioning/datasources/prometheus-honeypot.yml`
- Create: `deploy/grafana/provisioning/datasources/prometheus-mailcow.yml`
- Create: `deploy/grafana/provisioning/datasources/prometheus-wordpress.yml`

- [ ] **Step 1: Create `prometheus-honeypot.yml`**

  Write to `deploy/grafana/provisioning/datasources/prometheus-honeypot.yml`:

  ```yaml
  apiVersion: 1
  datasources:
    - name: "Prometheus — Honeypot"
      type: prometheus
      access: proxy
      uid: prom-honeypot
      url: http://167.233.115.41:9101
      editable: false
  ```

- [ ] **Step 2: Create `prometheus-mailcow.yml`**

  Write to `deploy/grafana/provisioning/datasources/prometheus-mailcow.yml`:

  ```yaml
  apiVersion: 1
  datasources:
    - name: "Prometheus — Mailcow"
      type: prometheus
      access: proxy
      uid: prom-mailcow
      url: http://100.120.31.14:9101
      editable: false
  ```

- [ ] **Step 3: Create `prometheus-wordpress.yml`**

  Write to `deploy/grafana/provisioning/datasources/prometheus-wordpress.yml`:

  ```yaml
  apiVersion: 1
  datasources:
    - name: "Prometheus — WordPress"
      type: prometheus
      access: proxy
      uid: prom-wordpress
      url: http://100.92.58.24:9101
      editable: false
  ```

- [ ] **Step 4: Verify all three files parse as valid YAML**

  ```bash
  python3 -c "
  import yaml, pathlib
  for f in [
      'deploy/grafana/provisioning/datasources/prometheus-honeypot.yml',
      'deploy/grafana/provisioning/datasources/prometheus-mailcow.yml',
      'deploy/grafana/provisioning/datasources/prometheus-wordpress.yml',
  ]:
      d = yaml.safe_load(pathlib.Path(f).read_text())
      ds = d['datasources'][0]
      print(f\"{ds['uid']}: name={ds['name']!r} url={ds['url']!r}\")
  print('OK: all three datasource files valid')
  "
  ```

  Expected output:
  ```
  prom-honeypot: name='Prometheus — Honeypot' url='http://167.233.115.41:9101'
  prom-mailcow: name='Prometheus — Mailcow' url='http://100.120.31.14:9101'
  prom-wordpress: name='Prometheus — WordPress' url='http://100.92.58.24:9101'
  OK: all three datasource files valid
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add deploy/grafana/provisioning/datasources/prometheus-honeypot.yml \
          deploy/grafana/provisioning/datasources/prometheus-mailcow.yml \
          deploy/grafana/provisioning/datasources/prometheus-wordpress.yml
  git commit -m "feat(grafana): add per-node Prometheus datasources for effectiveness dashboard"
  ```

---

## Task 2: Effectiveness dashboard JSON

**Files:**
- Create: `deploy/grafana/provisioning/dashboards/swarmguard-effectiveness.json`

The dashboard has 24 data panels plus 6 row headers = 30 panel objects total. Writing them by hand invites subtle JSON errors. Generate and validate with Python instead.

### Panel layout reference

```
y=0:  Row header "Blocked IPs"         id=1
y=1:  Blocked IPs (h=4, stat)          ids 2/3/4   x=0/8/16
y=5:  Row header "Block rate"          id=5
y=6:  Block rate (h=6, timeseries)     ids 6/7/8   x=0/8/16
y=12: Row header "Events received"     id=9
y=13: Events/min (h=6, timeseries)     ids 10/11/12  x=0/8/16
y=19: Row header "Federation in"       id=13
y=20: Federation in (h=6, timeseries)  ids 14/15/16  x=0/8/16
y=26: Row header "Candidates"          id=17
y=27: Candidates (h=8, table)          ids 18/19/20  x=0/8/16
y=35: Row header "Recidivism"          id=21
y=36: Recidivism (h=4, stat)           ids 22/23/24  x=0/8/16
```

### Nodes and datasource UIDs

| Node label | UID | x position |
|---|---|---|
| Honeypot | prom-honeypot | 0 |
| Mailcow | prom-mailcow | 8 |
| WordPress | prom-wordpress | 16 |

- [ ] **Step 1: Generate the dashboard JSON using Python**

  Run the following Python script (inline — no separate file needed):

  ```bash
  python3 << 'PYEOF'
  import json

  NODES = [
      ("Honeypot",   "prom-honeypot",   0),
      ("Mailcow",    "prom-mailcow",    8),
      ("WordPress",  "prom-wordpress",  16),
  ]

  def ds(uid):
      return {"type": "prometheus", "uid": uid}

  def row(panel_id, title, y):
      return {
          "collapsed": False,
          "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
          "id": panel_id,
          "title": title,
          "type": "row",
      }

  def stat_panel(panel_id, title, uid, expr, y, x, color_mode="thresholds"):
      p = {
          "datasource": ds(uid),
          "fieldConfig": {
              "defaults": {
                  "color": {"mode": color_mode},
                  "thresholds": {
                      "mode": "absolute",
                      "steps": [
                          {"color": "green", "value": None},
                          {"color": "red",   "value": 1},
                      ],
                  },
              },
              "overrides": [],
          },
          "gridPos": {"h": 4, "w": 8, "x": x, "y": y},
          "id": panel_id,
          "options": {
              "colorMode": "value",
              "graphMode": "none",
              "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
          },
          "targets": [
              {
                  "datasource": ds(uid),
                  "expr": expr,
                  "instant": True,
                  "refId": "A",
              }
          ],
          "title": title,
          "type": "stat",
      }
      if color_mode != "thresholds":
          p["fieldConfig"]["defaults"].pop("thresholds")
          p["fieldConfig"]["defaults"]["color"] = {"mode": "fixed", "fixedColor": "blue"}
      return p

  def timeseries_panel(panel_id, title, uid, expr, y, x, h=6, unit="short", draw_style="bars"):
      return {
          "datasource": ds(uid),
          "fieldConfig": {
              "defaults": {
                  "color": {"mode": "palette-classic"},
                  "custom": {
                      "drawStyle": draw_style,
                      "fillOpacity": 20,
                      "lineWidth": 1,
                  },
                  "unit": unit,
              },
              "overrides": [],
          },
          "gridPos": {"h": h, "w": 8, "x": x, "y": y},
          "id": panel_id,
          "options": {"tooltip": {"mode": "single"}},
          "targets": [
              {
                  "datasource": ds(uid),
                  "expr": expr,
                  "legendFormat": "__auto",
                  "refId": "A",
              }
          ],
          "title": title,
          "type": "timeseries",
      }

  def table_panel(panel_id, title, uid, expr, y, x):
      return {
          "datasource": ds(uid),
          "fieldConfig": {
              "defaults": {},
              "overrides": [
                  {
                      "matcher": {"id": "byName", "options": "ip"},
                      "properties": [{"id": "displayName", "value": "IP"}],
                  },
                  {
                      "matcher": {"id": "byName", "options": "Value"},
                      "properties": [{"id": "displayName", "value": "Score"}],
                  },
              ],
          },
          "gridPos": {"h": 8, "w": 8, "x": x, "y": y},
          "id": panel_id,
          "options": {"sortBy": [{"displayName": "Score", "desc": True}]},
          "targets": [
              {
                  "datasource": ds(uid),
                  "expr": expr,
                  "format": "table",
                  "instant": True,
                  "legendFormat": "{{ip}}",
                  "refId": "A",
              }
          ],
          "title": title,
          "type": "table",
      }

  panels = []

  # Row 1 — Blocked IPs
  panels.append(row(1, "Blocked IPs", y=0))
  for pid, (label, uid, x) in zip([2, 3, 4], NODES):
      panels.append(stat_panel(
          pid, f"Blocked IPs — {label}", uid,
          "sum(swarmguard_blocked_ips)", y=1, x=x,
      ))

  # Row 2 — Block rate
  panels.append(row(5, "Block rate", y=5))
  for pid, (label, uid, x) in zip([6, 7, 8], NODES):
      panels.append(timeseries_panel(
          pid, f"Block rate — {label}", uid,
          "sum(increase(swarmguard_blocks_total[$__interval]))",
          y=6, x=x, h=6, draw_style="bars",
      ))

  # Row 3 — Events received
  panels.append(row(9, "Events received", y=12))
  for pid, (label, uid, x) in zip([10, 11, 12], NODES):
      panels.append(timeseries_panel(
          pid, f"Events/min — {label}", uid,
          "sum(rate(swarmguard_events_received_total[$__interval])) * 60",
          y=13, x=x, h=6, unit="reqpm", draw_style="lines",
      ))

  # Row 4 — Federation in
  panels.append(row(13, "Federation in", y=19))
  for pid, (label, uid, x) in zip([14, 15, 16], NODES):
      panels.append(timeseries_panel(
          pid, f"Federation in — {label}", uid,
          'rate(swarmguard_events_federated_total{direction="in"}[$__interval]) * 60',
          y=20, x=x, h=6, unit="reqpm", draw_style="lines",
      ))

  # Row 5 — Candidates
  panels.append(row(17, "Candidates (approaching block threshold)", y=26))
  for pid, (label, uid, x) in zip([18, 19, 20], NODES):
      panels.append(table_panel(
          pid, f"Candidates — {label}", uid,
          "swarmguard_ip_score < $block_threshold",
          y=27, x=x,
      ))

  # Row 6 — Recidivism
  panels.append(row(21, "Recidivism", y=35))
  for pid, (label, uid, x) in zip([22, 23, 24], NODES):
      p = stat_panel(
          pid, f"Recidivism — {label}", uid,
          "sum(swarmguard_block_recurrence_total)",
          y=36, x=x, color_mode="fixed",
      )
      # No threshold colouring — informational stat
      p["fieldConfig"]["defaults"]["color"] = {"mode": "fixed", "fixedColor": "blue"}
      p["fieldConfig"]["defaults"].pop("thresholds", None)
      panels.append(p)

  dashboard = {
      "id": None,
      "uid": "swarmguard-effectiveness",
      "title": "SwarmGuard — Effectiveness",
      "tags": ["swarmguard"],
      "schemaVersion": 38,
      "version": 1,
      "refresh": "30s",
      "time": {"from": "now-1h", "to": "now"},
      "timepicker": {},
      "templating": {
          "list": [
              {
                  "hide": 0,
                  "label": "Block threshold",
                  "name": "block_threshold",
                  "query": "80",
                  "skipUrlSync": False,
                  "type": "constant",
              }
          ]
      },
      "annotations": {"list": []},
      "panels": panels,
  }

  out = json.dumps(dashboard, indent=2, ensure_ascii=False)
  with open("deploy/grafana/provisioning/dashboards/swarmguard-effectiveness.json", "w") as f:
      f.write(out)
  print(f"Written: {len(panels)} panels, {len(out)} bytes")
  PYEOF
  ```

  Expected output:
  ```
  Written: 30 panels, <N> bytes
  ```

- [ ] **Step 2: Validate JSON structure and layout**

  ```bash
  python3 -c "
  import json
  from pathlib import Path

  d = json.loads(Path('deploy/grafana/provisioning/dashboards/swarmguard-effectiveness.json').read_text())

  assert d['uid'] == 'swarmguard-effectiveness', f\"uid wrong: {d['uid']}\"
  assert d['title'] == 'SwarmGuard — Effectiveness', f\"title wrong: {d['title']}\"

  # Check template variable
  names = [v['name'] for v in d['templating']['list']]
  assert 'block_threshold' in names, f'block_threshold missing from templating: {names}'

  # Check panel count
  assert len(d['panels']) == 30, f'expected 30 panels (6 rows + 24 data), got {len(d[\"panels\"])}'

  by_id = {p['id']: p for p in d['panels']}

  # Row headers
  for rid, expected_y, expected_title in [
      (1,  0,  'Blocked IPs'),
      (5,  5,  'Block rate'),
      (9,  12, 'Events received'),
      (13, 19, 'Federation in'),
      (17, 26, 'Candidates (approaching block threshold)'),
      (21, 35, 'Recidivism'),
  ]:
      p = by_id[rid]
      assert p['type'] == 'row', f'id={rid} should be row, got {p[\"type\"]}'
      assert p['gridPos']['y'] == expected_y, f'row id={rid} y={p[\"gridPos\"][\"y\"]}, want {expected_y}'

  # Data panels — spot check positions and datasource UIDs
  checks = [
      # (id, type, y, x, uid_suffix)
      (2,  'stat',       1,  0,  'prom-honeypot'),
      (3,  'stat',       1,  8,  'prom-mailcow'),
      (4,  'stat',       1,  16, 'prom-wordpress'),
      (6,  'timeseries', 6,  0,  'prom-honeypot'),
      (8,  'timeseries', 6,  16, 'prom-wordpress'),
      (10, 'timeseries', 13, 0,  'prom-honeypot'),
      (14, 'timeseries', 20, 0,  'prom-honeypot'),
      (18, 'table',      27, 0,  'prom-honeypot'),
      (20, 'table',      27, 16, 'prom-wordpress'),
      (22, 'stat',       36, 0,  'prom-honeypot'),
      (24, 'stat',       36, 16, 'prom-wordpress'),
  ]
  for pid, ptype, py, px, uid in checks:
      p = by_id[pid]
      assert p['type'] == ptype, f'id={pid} type={p[\"type\"]}, want {ptype}'
      assert p['gridPos']['y'] == py, f'id={pid} y={p[\"gridPos\"][\"y\"]}, want {py}'
      assert p['gridPos']['x'] == px, f'id={pid} x={p[\"gridPos\"][\"x\"]}, want {px}'
      assert p['gridPos']['w'] == 8,  f'id={pid} w={p[\"gridPos\"][\"w\"]}, want 8'
      ds_uid = p['datasource']['uid']
      assert ds_uid == uid, f'id={pid} datasource uid={ds_uid!r}, want {uid!r}'

  # Candidates query uses block_threshold variable
  assert '\$block_threshold' in by_id[18]['targets'][0]['expr'], 'candidates query missing \$block_threshold'
  assert '\$block_threshold' in by_id[19]['targets'][0]['expr'], 'candidates query missing \$block_threshold'
  assert '\$block_threshold' in by_id[20]['targets'][0]['expr'], 'candidates query missing \$block_threshold'

  # Candidates table height
  assert by_id[18]['gridPos']['h'] == 8, f'candidates h={by_id[18][\"gridPos\"][\"h\"]}, want 8'

  print(f'OK: {len(d[\"panels\"])} panels, layout correct, datasource UIDs correct')
  "
  ```

  Expected output:
  ```
  OK: 30 panels, layout correct, datasource UIDs correct
  ```

- [ ] **Step 3: Commit**

  ```bash
  git add deploy/grafana/provisioning/dashboards/swarmguard-effectiveness.json
  git commit -m "feat(grafana): add SwarmGuard Effectiveness dashboard with per-node Prometheus panels"
  ```

- [ ] **Step 4: Reload Grafana and verify**

  ```bash
  docker compose -f /container/compose/grafana/docker-compose.yml restart grafana
  ```

  Then open `http://grafana.joesnuc:3030` and confirm:
  - Three new datasources appear in Grafana → Connections: "Prometheus — Honeypot", "Prometheus — Mailcow", "Prometheus — WordPress"
  - "SwarmGuard — Effectiveness" dashboard appears in the dashboard list
  - Six rows visible, each with three panels (honeypot | mailcow | wordpress)
  - "Block threshold" variable appears in the variables bar (default: 80)
  - Blocked IPs stats show non-zero values for mailcow and wordpress (they have lower thresholds)
  - Federation in timeseries shows activity on mailcow and wordpress

  Optional smoke-test from host:
  ```bash
  curl -sf http://167.233.115.41:9101/metrics | grep swarmguard_blocked_ips
  curl -sf http://100.120.31.14:9101/metrics  | grep swarmguard_blocked_ips
  curl -sf http://100.92.58.24:9101/metrics   | grep swarmguard_blocked_ips
  ```
