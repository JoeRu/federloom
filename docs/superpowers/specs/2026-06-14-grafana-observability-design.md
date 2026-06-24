# Grafana Observability Design

**Goal:** Add an optional observability plane to FederLoom that feeds a Grafana dashboard with live metrics (Prometheus) and full event history with due-time computation (SQLite).

**Architecture:** A thin `Observer` struct in `internal/observability` hooks into the Node event pipeline as a synchronous write-fan-out. Two independent outputs — a Prometheus HTTP server and a SQLite appender — are each enabled by config. Neither output is on the critical enforcement path; a failed write logs and continues.

**Tech Stack:** Go standard library (`net/http`, `database/sql`), `modernc.org/sqlite` (pure-Go SQLite driver, no CGo), `github.com/prometheus/client_golang`, Grafana JSON dashboard provisioning.

---

## 1. Observer Architecture

`Observer` is created by `Node.New()` when `observability` is non-empty in config. The Node passes it as three call-sites in the event pipeline:

```
ingest event arrives
  → Node.run()
      → reputation.Record()   ─┐
      → rules.Eval()           ├─→ Observer.RecordEvent(event, scoreAfter, ruleName, action)
      → enforce.Block(ip)      ──→ Observer.RecordBlock(ip, scoreAtBlock, expectedUnblock)
      → enforce.Unblock(ip)    ──→ Observer.RecordUnblock(ip)
```

`RecordEvent` writes one row to `events` and one to `rule_firings` (if a rule matched), then updates Prometheus counters. `RecordBlock` / `RecordUnblock` update the `blocks` table and the `federloom_blocked_ips` gauge.

All writes are synchronous and non-blocking to the caller. SQLite write errors are logged; Prometheus updates never fail. Observer holds no channels or goroutines on the hot path. A single background goroutine runs the daily retention sweep.

### Files

| File | Responsibility |
|---|---|
| `internal/observability/observer.go` | `Observer` struct, constructor, public call-sites |
| `internal/observability/prometheus.go` | Metric definitions (`prometheus/client_golang`), HTTP server start/stop |
| `internal/observability/sqlite.go` | Schema init, row appenders, retention sweep goroutine |

---

## 2. Prometheus Metrics

HTTP server binds to `observability.prometheus_addr` (default `:9101`). Plain HTTP, no TLS — consistent with CrowdSec's own exporter. Empty string disables the server entirely.

All metrics share the namespace `federloom_`:

| Metric | Type | Labels | Description |
|---|---|---|---|
| `federloom_events_received_total` | Counter | `reason`, `reporter_id` | Incremented on every ingest event reaching the reputation engine |
| `federloom_rules_fired_total` | Counter | `rule`, `action` | Incremented when a rule matches (`block`/`watch`/`ignore`) |
| `federloom_blocked_ips` | Gauge | — | Current count of IPs in the enforced block set |
| `federloom_ip_score` | Gauge | `ip` | Current score for IPs at or above `score_gauge_threshold`; omitted for low-score IPs to bound cardinality |
| `federloom_federation_peers` | Gauge | — | Connected libp2p gossipsub peers; 0 in solo/federated-client mode |
| `federloom_events_federated_total` | Counter | `direction` (`in`/`out`) | Gossip messages received/published |

**Cardinality guard:** `federloom_ip_score` series are only created for IPs whose score ≥ `score_gauge_threshold`. When `score_gauge_threshold` is 0 (default), it is treated as `block_threshold / 2`. When a score drops below the threshold its gauge series is deleted via `prometheus.GaugeVec.Delete()`.

---

## 3. SQLite Schema

Database file at `observability.sqlite_path` (resolved relative to `store.dir` if not absolute). Empty string disables SQLite entirely.

```sql
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    ip       TEXT    NOT NULL,
    reason   TEXT    NOT NULL,
    reporter TEXT    NOT NULL,
    subnet   TEXT    NOT NULL DEFAULT '',
    score    REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_firings (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    ip     TEXT    NOT NULL,
    rule   TEXT    NOT NULL,
    action TEXT    NOT NULL,
    score  REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ip               TEXT    NOT NULL,
    blocked_at       INTEGER NOT NULL,
    unblocked_at     INTEGER,
    score_at_block   REAL    NOT NULL,
    expected_unblock INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS rule_firings_ts ON rule_firings(ts);
CREATE INDEX IF NOT EXISTS blocks_ip       ON blocks(ip);
```

**Due-time computation:** `expected_unblock` is a unix timestamp computed once at block time:

```
expected_unblock = blocked_at + halfLife × log2(scoreAtBlock / blockThreshold)
```

where `halfLife` and `blockThreshold` come from `reputation` config. Stored as an integer unix timestamp; Grafana queries it as `datetime(expected_unblock, 'unixepoch')`.

**Retention sweep:** A goroutine started by `Observer.Start()` ticks every 24 hours and runs:

```sql
DELETE FROM events       WHERE ts < ?;
DELETE FROM rule_firings WHERE ts < ?;
DELETE FROM blocks       WHERE ts < ? AND unblocked_at IS NOT NULL;
```

where `?` = `now - retention`. Active blocks (`unblocked_at IS NULL`) are never pruned regardless of age. Retention is configured via `observability.sqlite_retention` (default `360h` = 15 days).

**SQLite driver:** `modernc.org/sqlite` — pure Go, no CGo, no shared library dependency. Added to `go.mod`.

---

## 4. Config

New optional section in `internal/config/config.go`:

```go
type ObservabilityConfig struct {
    PrometheusAddr      string   `yaml:"prometheus_addr"`       // default ":9101"; "" = disabled
    SQLitePath          string   `yaml:"sqlite_path"`           // default ""; "" = disabled
    SQLiteRetention     Duration `yaml:"sqlite_retention"`      // default 360h (15 days)
    ScoreGaugeThreshold float64  `yaml:"score_gauge_threshold"` // default 0 = half of block_threshold
}
```

Added to `Config` as `Observability ObservabilityConfig yaml:"observability"`.

**Per-deployment defaults:**

| Deployment | `prometheus_addr` | `sqlite_path` | Notes |
|---|---|---|---|
| `deploy/honeypot/config.yaml` | `:9101` | `metrics.db` | Both outputs |
| `deploy/mailcow/config.yaml` | `:9101` | _(empty)_ | Prometheus only |
| `deploy/wordpress/config.yaml` | `:9101` | _(empty)_ | Prometheus only |
| `deploy/client/config.yaml` | _(empty)_ | _(empty)_ | Unchanged — smoke-test only |
| `deploy/examples/config.solo.yaml` | _(commented)_ | _(commented)_ | Example snippet |

---

## 5. Dashboard

### Files

```
deploy/grafana/
  federloom-dashboard.json               ← importable dashboard export
  provisioning/
    dashboards/
      federloom.yml                      ← Grafana provisioning pointer
    datasources/
      federloom-sqlite.yml               ← SQLite datasource pre-config
```

`federloom-dashboard.json` is a standard Grafana JSON model. Operators on remote nodes (no SQLite) import it and the SQLite row panels show "No data" gracefully — they do not break the Prometheus panels.

### Dashboard Variable

One template variable `$node` populated from `label_values(federloom_events_received_total, job)`. All Prometheus panels append `{job="$node"}`. Set to `All` by default.

### Panels

**Row 1 — Live (Prometheus datasource)**

| Panel | Visualization | Query |
|---|---|---|
| Events/min by reason | Timeseries | `rate(federloom_events_received_total{job="$node"}[5m]) * 60` grouped by `reason` |
| Rule firings by action | Timeseries | `rate(federloom_rules_fired_total{job="$node"}[5m]) * 60` grouped by `action` |
| Blocked IPs | Stat | `federloom_blocked_ips{job="$node"}` |
| Federation peers | Stat | `federloom_federation_peers{job="$node"}` |
| Top 10 reporters | Bar chart | `topk(10, sum by(reporter_id)(federloom_events_received_total{job="$node"}))` |

**Row 2 — History (SQLite datasource, local node only)**

| Panel | Visualization | Query |
|---|---|---|
| Event log | Table | `SELECT datetime(ts,'unixepoch') AS time, ip, reason, reporter, ROUND(score,1) AS score FROM events ORDER BY ts DESC LIMIT 200` |
| Active blocks + due-time | Table | `SELECT ip, ROUND(score_at_block,1) AS score, datetime(expected_unblock,'unixepoch') AS due_time FROM blocks WHERE unblocked_at IS NULL ORDER BY expected_unblock ASC` |
| Rule firings (recent) | Table | `SELECT datetime(ts,'unixepoch') AS time, ip, rule, action, ROUND(score,1) AS score FROM rule_firings ORDER BY ts DESC LIMIT 200` |

### Grafana Provisioning Files

`deploy/grafana/provisioning/dashboards/federloom.yml`:
```yaml
apiVersion: 1
providers:
  - name: FederLoom
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards
```

`deploy/grafana/provisioning/datasources/federloom-sqlite.yml`:
```yaml
apiVersion: 1
datasources:
  - name: FederLoom SQLite
    type: frser-sqlite-datasource
    access: proxy
    jsonData:
      path: /var/lib/federloom/metrics.db
```

### Local Grafana Wiring

`/container/compose/grafana/docker-compose.yml` gets two additions under the `grafana` service:

```yaml
volumes:
  - federloom-data:/var/lib/federloom:ro
  - /root/federloom/deploy/grafana/provisioning/dashboards:/etc/grafana/provisioning/dashboards/federloom:ro
  - /root/federloom/deploy/grafana/provisioning/datasources:/etc/grafana/provisioning/datasources/federloom:ro
```

And at the bottom of the Grafana compose, declare the external volume:

```yaml
volumes:
  grafana-storage:
    external: true
  federloom-data:
    external: true
```

`/container/compose/prometheus/prometheus.yml` gets three new scrape jobs:

```yaml
- job_name: "federloom-honeypot"
  scrape_interval: "30s"
  static_configs:
    - targets: ['host.docker.internal:9101']

- job_name: "federloom-mailcow"
  scrape_interval: "30s"
  static_configs:
    - targets: ['100.120.31.14:9101']

- job_name: "federloom-wordpress"
  scrape_interval: "30s"
  static_configs:
    - targets: ['100.92.58.24:9101']
```

---

## 6. Node Wiring

`internal/node/node.go` changes:

1. `Node` gains a field `obs *observability.Observer` (nil when disabled).
2. `New()` calls `observability.New(cfg.Observability, cfg.Reputation)` and stores it. Returns error if either output fails to initialise (e.g. SQLite schema migration error).
3. `Node.Start()` calls `obs.Start(ctx)` which launches the retention goroutine and starts the Prometheus HTTP server.
4. In `Node.run()`, after `rep.Record()` and `rules.Eval()`, a single helper call `n.observe(event, score, matchedRule, action)` fans out to Observer — no-ops when `obs` is nil.
5. `enforce.Block()` / `enforce.Unblock()` calls are wrapped similarly.

---

## 7. Testing

- `internal/observability/prometheus_test.go`: start Observer with Prometheus only, fire events, scrape `/metrics`, assert counter values.
- `internal/observability/sqlite_test.go`: start Observer with SQLite only, fire events/blocks/unblocks, query rows, assert retention sweep deletes old rows.
- No integration test changes required (adversarial suite does not exercise observability).

---

## 8. Deliverables Checklist

- [ ] `internal/observability/observer.go`
- [ ] `internal/observability/prometheus.go`
- [ ] `internal/observability/sqlite.go`
- [ ] `internal/observability/prometheus_test.go`
- [ ] `internal/observability/sqlite_test.go`
- [ ] `internal/config/config.go` — `ObservabilityConfig`
- [ ] `internal/node/node.go` — wire Observer
- [ ] `deploy/honeypot/config.yaml` — enable both outputs
- [ ] `deploy/mailcow/config.yaml` — enable Prometheus
- [ ] `deploy/wordpress/config.yaml` — enable Prometheus
- [ ] `deploy/examples/config.solo.yaml` — commented example
- [ ] `deploy/grafana/federloom-dashboard.json`
- [ ] `deploy/grafana/provisioning/dashboards/federloom.yml`
- [ ] `deploy/grafana/provisioning/datasources/federloom-sqlite.yml`
- [ ] `/container/compose/grafana/docker-compose.yml` — volume mounts
- [ ] `/container/compose/prometheus/prometheus.yml` — 3 scrape jobs
- [ ] `CHANGELOG.md`
