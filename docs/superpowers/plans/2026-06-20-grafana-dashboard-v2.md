# Grafana Dashboard v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `block_threshold` dashboard variable, a "Connected peers" table, and a "Blocklist candidates" table to the existing SwarmGuard Grafana dashboard JSON.

**Architecture:** Pure JSON edits to `deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json`. No Go code changes. Two tasks: (1) add the template variable, (2) add the two new panels and shift existing SQLite panels down to make room.

**Tech Stack:** Grafana dashboard JSON, Prometheus datasource, Python for JSON validation.

---

## Context

The existing dashboard file is at:
```
deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json
```

Current panel layout (all panels are in this file's `panels` array):

| id | type | gridPos | title |
|----|------|---------|-------|
| 10 | row | y=0 | Live — Prometheus |
| 1 | timeseries | y=1,x=0,w=12,h=8 | Events / min by reason |
| 2 | timeseries | y=1,x=12,w=12,h=8 | Rule firings / min by action |
| 3 | stat | y=9,x=0,w=6,h=4 | Blocked IPs |
| 4 | stat | y=9,x=6,w=6,h=4 | Federation peers |
| 5 | barchart | y=9,x=12,w=12,h=8 | Top 10 reporters |
| 11 | row | y=17 | History — SQLite |
| 6 | table | y=18,w=24,h=8 | Event log (latest 200) |
| 7 | table | y=26,x=0,w=12,h=8 | Active blocks + due-time |
| 8 | table | y=26,x=12,w=12,h=8 | Rule firings (latest 200) |

After Task 2, the two new panels occupy y=17-24 (between the Live row content and the SQLite row). All SQLite panels shift down by 8.

The Prometheus datasource uid is `${DS_PROMETHEUS}`. The SQLite datasource uid is `${DS_SWARMGUARD_SQLITE}`.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json` | Modify | Add variable + two panels, shift SQLite panels |

---

## Task 1: Add `block_threshold` template variable

**Files:**
- Modify: `deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json`

- [ ] **Step 1: Add the variable to `templating.list`**

  Open `deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json`. Find the `"templating"` key. Its `"list"` array currently has one entry (the `node` query variable). Append the following object to that array:

  ```json
  {
    "hide": 0,
    "label": "Block threshold",
    "name": "block_threshold",
    "query": "80",
    "skipUrlSync": false,
    "type": "constant"
  }
  ```

  After the edit, `templating.list` has two entries: the existing `node` query variable, and the new `block_threshold` constant.

- [ ] **Step 2: Verify the JSON is valid and the variable is present**

  ```bash
  python3 -c "
  import json
  d = json.load(open('deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json'))
  names = [v['name'] for v in d['templating']['list']]
  assert 'block_threshold' in names, f'variable missing, got: {names}'
  bt = next(v for v in d['templating']['list'] if v['name'] == 'block_threshold')
  assert bt['type'] == 'constant', f\"type wrong: {bt['type']}\"
  assert bt['query'] == '80', f\"query wrong: {bt['query']}\"
  print('OK: block_threshold variable present')
  "
  ```

  Expected output:
  ```
  OK: block_threshold variable present
  ```

- [ ] **Step 3: Commit**

  ```bash
  git add deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json
  git commit -m "feat(grafana): add block_threshold constant variable to dashboard"
  ```

---

## Task 2: Add Connected peers and Blocklist candidates panels

**Files:**
- Modify: `deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json`

The two new panels go at y=17 (between the Live row's last content at y=16 and the SQLite row header, which currently sits at y=17). To make room, shift the SQLite row and all four SQLite panels down by 8.

- [ ] **Step 1: Shift existing SQLite panels down by 8**

  In `deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json`, update the `gridPos.y` value for these five panels:

  | id | current y | new y |
  |----|-----------|-------|
  | 11 (SQLite row header) | 17 | 25 |
  | 6 (Event log) | 18 | 26 |
  | 7 (Active blocks) | 26 | 34 |
  | 8 (Rule firings) | 26 | 34 |

  Find each panel by its `"id"` field and update only its `gridPos.y` value. No other fields change.

- [ ] **Step 2: Verify the shifts**

  ```bash
  python3 -c "
  import json
  d = json.load(open('deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json'))
  by_id = {p['id']: p for p in d['panels']}
  assert by_id[11]['gridPos']['y'] == 25, f\"row y={by_id[11]['gridPos']['y']}\"
  assert by_id[6]['gridPos']['y']  == 26, f\"event log y={by_id[6]['gridPos']['y']}\"
  assert by_id[7]['gridPos']['y']  == 34, f\"blocks y={by_id[7]['gridPos']['y']}\"
  assert by_id[8]['gridPos']['y']  == 34, f\"rule firings y={by_id[8]['gridPos']['y']}\"
  print('OK: SQLite panels shifted')
  "
  ```

  Expected:
  ```
  OK: SQLite panels shifted
  ```

- [ ] **Step 3: Add the "Connected peers" panel**

  Append the following object to the `panels` array in the dashboard JSON:

  ```json
  {
    "datasource": {
      "type": "prometheus",
      "uid": "${DS_PROMETHEUS}"
    },
    "fieldConfig": {
      "defaults": {},
      "overrides": [
        {
          "matcher": {"id": "byName", "options": "reporter_id"},
          "properties": [{"id": "displayName", "value": "Peer ID"}]
        },
        {
          "matcher": {"id": "byName", "options": "Value"},
          "properties": [{"id": "displayName", "value": "Events"}]
        }
      ]
    },
    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 17},
    "id": 12,
    "options": {
      "sortBy": [{"displayName": "Events", "desc": true}]
    },
    "targets": [
      {
        "datasource": {
          "type": "prometheus",
          "uid": "${DS_PROMETHEUS}"
        },
        "expr": "sum by (reporter_id) (increase(swarmguard_events_received_total{job=~\"$node\"}[$__range]))",
        "instant": true,
        "legendFormat": "{{reporter_id}}",
        "refId": "A"
      }
    ],
    "title": "Connected peers",
    "type": "table"
  }
  ```

- [ ] **Step 4: Add the "Blocklist candidates" panel**

  Append the following object to the `panels` array:

  ```json
  {
    "datasource": {
      "type": "prometheus",
      "uid": "${DS_PROMETHEUS}"
    },
    "fieldConfig": {
      "defaults": {},
      "overrides": [
        {
          "matcher": {"id": "byName", "options": "ip"},
          "properties": [{"id": "displayName", "value": "IP"}]
        },
        {
          "matcher": {"id": "byName", "options": "Value"},
          "properties": [{"id": "displayName", "value": "Score"}]
        }
      ]
    },
    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 17},
    "id": 13,
    "options": {
      "sortBy": [{"displayName": "Score", "desc": true}]
    },
    "targets": [
      {
        "datasource": {
          "type": "prometheus",
          "uid": "${DS_PROMETHEUS}"
        },
        "expr": "swarmguard_ip_score{job=~\"$node\"} < $block_threshold",
        "instant": true,
        "legendFormat": "{{ip}}",
        "refId": "A"
      }
    ],
    "title": "Blocklist candidates (score < $block_threshold)",
    "type": "table"
  }
  ```

- [ ] **Step 5: Verify the full dashboard structure**

  ```bash
  python3 -c "
  import json
  d = json.load(open('deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json'))
  by_id = {p['id']: p for p in d['panels']}

  # New panels exist
  assert 12 in by_id, 'Connected peers panel (id=12) missing'
  assert 13 in by_id, 'Blocklist candidates panel (id=13) missing'

  # New panels at correct position
  assert by_id[12]['gridPos'] == {'h': 8, 'w': 12, 'x': 0,  'y': 17}, f\"id=12 gridPos wrong: {by_id[12]['gridPos']}\"
  assert by_id[13]['gridPos'] == {'h': 8, 'w': 12, 'x': 12, 'y': 17}, f\"id=13 gridPos wrong: {by_id[13]['gridPos']}\"

  # Queries look right
  assert 'reporter_id' in by_id[12]['targets'][0]['expr'], 'peers query missing reporter_id'
  assert 'block_threshold' in by_id[13]['targets'][0]['expr'], 'candidates query missing block_threshold'

  # SQLite panels still shifted
  assert by_id[11]['gridPos']['y'] == 25
  assert by_id[6]['gridPos']['y']  == 26
  assert by_id[7]['gridPos']['y']  == 34
  assert by_id[8]['gridPos']['y']  == 34

  # Total panel count
  assert len(d['panels']) == 12, f'expected 12 panels, got {len(d[\"panels\"])}'

  print(f'OK: {len(d[\"panels\"])} panels, layout correct')
  "
  ```

  Expected:
  ```
  OK: 12 panels, layout correct
  ```

- [ ] **Step 6: Reload Grafana and visually verify**

  ```bash
  # Restart Grafana to pick up the provisioned dashboard changes
  # (adjust the compose file path to wherever Grafana runs in this environment)
  docker compose -f /container/compose/grafana/docker-compose.yml restart grafana
  ```

  Open the SwarmGuard dashboard in a browser. Confirm:
  - A "Block threshold" input appears in the dashboard variables bar (default: 80)
  - A "Connected peers" table appears between the "Top 10 reporters" barchart row and the SQLite history row
  - A "Blocklist candidates" table appears next to "Connected peers"
  - The SQLite history row ("History — SQLite") still appears below the new panels
  - No overlapping panels

  If the Grafana instance is not running locally, check using the smoke test script:
  ```bash
  curl -sf http://localhost:3000/api/dashboards/uid/swarmguard-v1 | python3 -c "
  import json, sys
  d = json.load(sys.stdin)
  panels = d['dashboard']['panels']
  titles = [p['title'] for p in panels]
  print('Panels:', titles)
  assert 'Connected peers' in titles
  assert 'Blocklist candidates (score < \$block_threshold)' in titles
  print('OK: both panels present in live Grafana')
  "
  ```

- [ ] **Step 7: Commit**

  ```bash
  git add deploy/grafana/provisioning/dashboards/swarmguard-dashboard.json
  git commit -m "feat(grafana): add Connected peers and Blocklist candidates panels"
  ```
