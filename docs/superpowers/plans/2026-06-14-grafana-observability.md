# Grafana Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional dual-output Observer to FederLoom that exposes a Prometheus `/metrics` endpoint and an append-only SQLite event log, then ship a Grafana dashboard covering all three FederLoom nodes.

**Architecture:** A thin `Observer` struct in `internal/observability` fans out to two optional outputs (Prometheus counters/gauges, SQLite row appenders). The Node wires Observer into its event pipeline at three call-sites: `RecordEvent`, `RecordBlock`, `RecordUnblock`. Both outputs are disabled by default (empty config values); enabling either requires only a one-line config change per deploy.

**Tech Stack:** Go `database/sql` + `modernc.org/sqlite` (pure-Go, no CGo), `github.com/prometheus/client_golang` (already an indirect dep — promote to direct), Grafana JSON dashboard provisioning.

---

## File Map

| File | Change |
|---|---|
| `internal/config/config.go` | Add `ObservabilityConfig`, add to `Config` struct and `Defaults()` |
| `internal/rules/rule.go` | Change `Evaluate` to return `(Action, string)` (action + rule name) |
| `internal/rules/rule_test.go` | Add helper to absorb second return value; fix all call-sites |
| `internal/observability/prometheus.go` | New — metric definitions + HTTP server |
| `internal/observability/prometheus_test.go` | New — counter/gauge/threshold tests |
| `internal/observability/sqlite.go` | New — schema init, row appenders, retention sweep |
| `internal/observability/sqlite_test.go` | New — insert/query/sweep tests |
| `internal/observability/observer.go` | New — fan-out struct wiring both outputs |
| `internal/node/node.go` | Add `obs` field, wire three call-sites + peers ticker |
| `deploy/honeypot/config.yaml` | Add `observability:` section (both outputs) |
| `deploy/honeypot/docker-compose.yml` | Expose port 9101 |
| `deploy/mailcow/config.yaml` | Add `observability:` (Prometheus only) |
| `deploy/wordpress/config.yaml` | Add `observability:` (Prometheus only) |
| `deploy/examples/config.solo.yaml` | Add commented `observability:` example |
| `deploy/grafana/federloom-dashboard.json` | New — Grafana dashboard export |
| `deploy/grafana/provisioning/dashboards/federloom.yml` | New — provisioning pointer |
| `deploy/grafana/provisioning/datasources/federloom-sqlite.yml` | New — SQLite datasource config |
| `/container/compose/grafana/docker-compose.yml` | Add volume mounts for SQLite + provisioning |
| `/container/compose/prometheus/prometheus.yml` | Add three federloom scrape jobs |
| `CHANGELOG.md` | Entry |

---

## Task 1: ObservabilityConfig in config.go

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write a failing test for ObservabilityConfig unmarshalling**

Add to `internal/config/config_test.go`:

```go
func TestObservabilityConfig_YAML(t *testing.T) {
	yaml := `
observability:
  prometheus_addr: ":9101"
  sqlite_path: "metrics.db"
  sqlite_retention: 360h
  score_gauge_threshold: 30
`
	cfg, err := LoadYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if cfg.Observability.PrometheusAddr != ":9101" {
		t.Errorf("PrometheusAddr = %q, want :9101", cfg.Observability.PrometheusAddr)
	}
	if cfg.Observability.SQLitePath != "metrics.db" {
		t.Errorf("SQLitePath = %q, want metrics.db", cfg.Observability.SQLitePath)
	}
	if cfg.Observability.SQLiteRetention.Duration != 360*time.Hour {
		t.Errorf("SQLiteRetention = %v, want 360h", cfg.Observability.SQLiteRetention.Duration)
	}
	if cfg.Observability.ScoreGaugeThreshold != 30 {
		t.Errorf("ScoreGaugeThreshold = %v, want 30", cfg.Observability.ScoreGaugeThreshold)
	}
}

func TestObservabilityConfig_Defaults(t *testing.T) {
	cfg := Defaults()
	// All fields zero/empty = observability disabled by default (spec §11.2).
	if cfg.Observability.PrometheusAddr != "" {
		t.Errorf("default PrometheusAddr should be empty, got %q", cfg.Observability.PrometheusAddr)
	}
	if cfg.Observability.SQLitePath != "" {
		t.Errorf("default SQLitePath should be empty, got %q", cfg.Observability.SQLitePath)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /root/federloom && go test ./internal/config/... -run TestObservability -v
```

Expected: FAIL with "cfg.Observability undefined"

- [ ] **Step 3: Add ObservabilityConfig to config.go**

In `internal/config/config.go`, add the struct and field. The struct goes after `TrustConfig`. The `Config` struct and `Defaults()` function are modified:

```go
// ObservabilityConfig controls the optional observability plane (spec §11.2).
// Both outputs are disabled by default; set non-empty values to enable.
type ObservabilityConfig struct {
	PrometheusAddr      string   `yaml:"prometheus_addr"`       // e.g. ":9101"; "" = disabled
	SQLitePath          string   `yaml:"sqlite_path"`           // path to metrics.db; "" = disabled
	SQLiteRetention     Duration `yaml:"sqlite_retention"`      // rows older than this are pruned
	ScoreGaugeThreshold float64  `yaml:"score_gauge_threshold"` // 0 = half of block_threshold
}
```

Add `Observability ObservabilityConfig \`yaml:"observability"\`` to the `Config` struct after `Trust TrustConfig`:

```go
type Config struct {
	FederationMode string              `yaml:"federation_mode"`
	Store          StoreConfig         `yaml:"store"`
	Reputation     ReputationConfig    `yaml:"reputation"`
	Ingest         IngestConfig        `yaml:"ingest"`
	Enforce        EnforceConfig       `yaml:"enforce"`
	Trust          TrustConfig         `yaml:"trust"`
	Observability  ObservabilityConfig `yaml:"observability"`
}
```

`Defaults()` needs no change — zero values mean disabled, which is correct.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /root/federloom && go test ./internal/config/... -v
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add ObservabilityConfig for optional metrics plane"
```

---

## Task 2: Return rule name from rules.Evaluate

The Prometheus metric `federloom_rules_fired_total` needs a `rule` label. `Evaluate` currently returns only `Action`; change it to `(Action, string)` where the string is the matched rule's name.

**Files:**
- Modify: `internal/rules/rule.go`
- Modify: `internal/rules/rule_test.go`
- Modify: `internal/node/node.go` (fix the two call-sites — only compile fix, no logic change yet)

- [ ] **Step 1: Update rule_test.go to add an eval helper**

Add this helper at the top of `internal/rules/rule_test.go` (after the existing helpers), and update every call to `rs.Evaluate` to use it — this way test logic stays unchanged:

```go
// eval is a test helper that discards the rule-name return value for brevity.
func eval(rs *RuleSet, e proto.Event, rec store.ScoreRecord, b *BurstStore) Action {
	a, _ := rs.Evaluate(e, rec, b)
	return a
}
```

Then replace every occurrence of `rs.Evaluate(` in the test file with `eval(rs, ` — for example:

```go
// Before:
if got := rs.Evaluate(ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionBlock {

// After:
if got := eval(rs, ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionBlock {
```

Also add a test verifying the rule name is returned:

```go
func TestEvaluate_ReturnsRuleName(t *testing.T) {
	path := writeRules(t, `
- name: my-rule
  reason: ssh-probe
  min_corroboration: 1
  action: block
`)
	rs := Load(path, 75)
	action, name := rs.Evaluate(ev("ssh-probe"), recCorr(1), emptyBurst())
	if action != ActionBlock {
		t.Errorf("action = %v, want block", action)
	}
	if name != "my-rule" {
		t.Errorf("name = %q, want my-rule", name)
	}
}

func TestEvaluate_NoMatch_EmptyName(t *testing.T) {
	rs := Load("", 75)
	_, name := rs.Evaluate(ev("ssh-probe"), recScore(10), emptyBurst())
	if name != "" {
		t.Errorf("name = %q, want empty on no match", name)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /root/federloom && go test ./internal/rules/... -run TestEvaluate_ReturnsRuleName -v
```

Expected: FAIL with "too many return values"

- [ ] **Step 3: Change Evaluate signature in rule.go**

In `internal/rules/rule.go`, change the function signature and two return statements:

```go
// Evaluate returns the action and matched rule name for the given event + reputation state.
// Rule name is empty when no rule matched (legacy fallback or ActionNone).
func (rs *RuleSet) Evaluate(e proto.Event, rec store.ScoreRecord, b *BurstStore) (Action, string) {
	rs.maybeReload()

	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if len(rs.rules) == 0 {
		if rec.Score >= rs.fallback {
			return ActionBlock, ""
		}
		return ActionNone, ""
	}

	now := time.Now()
	burstCache := make(map[burstCacheKey]int)

	for _, r := range rs.rules {
		if r.Reason != "" && r.Reason != e.Reason {
			continue
		}
		if r.MinScore > 0 && rec.Score < r.MinScore {
			continue
		}
		if r.MinCorroboration > 0 && rec.Corroboration < r.MinCorroboration {
			continue
		}
		if r.AnchoredOnly && rec.StrangerSeen {
			continue
		}
		if r.MinBurst > 0 {
			w := r.BurstWindow.Duration
			ck := burstCacheKey{reason: e.Reason, window: w}
			cnt, ok := burstCache[ck]
			if !ok {
				cnt = b.Count(e.IP, e.Reason, w, now)
				burstCache[ck] = cnt
			}
			if cnt < r.MinBurst {
				continue
			}
		}
		return r.Action, r.Name
	}
	return ActionNone, ""
}
```

- [ ] **Step 4: Fix node.go compile errors (two call-sites)**

In `internal/node/node.go`, find the two `n.rules.Evaluate(` calls (in `processLocal` and `ProcessRemote`) and capture the second return value:

```go
// In processLocal — change:
switch n.rules.Evaluate(e, rec, n.burst) {

// To:
action, _ := n.rules.Evaluate(e, rec, n.burst)
switch action {
```

```go
// In ProcessRemote — change:
switch n.rules.Evaluate(e, rec, n.burst) {

// To:
action, _ := n.rules.Evaluate(e, rec, n.burst)
switch action {
```

The `_` is intentional for now — Task 6 replaces it with the real rule name for Observer.

- [ ] **Step 5: Run all tests**

```bash
cd /root/federloom && go test ./... -race
```

Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add internal/rules/rule.go internal/rules/rule_test.go internal/node/node.go
git commit -m "feat(rules): return matched rule name from Evaluate"
```

---

## Task 3: Prometheus output

**Files:**
- Create: `internal/observability/prometheus.go`
- Create: `internal/observability/prometheus_test.go`

`prometheus/client_golang` is already an indirect dependency. Promote it to direct:

```bash
cd /root/federloom && go get github.com/prometheus/client_golang/prometheus
```

- [ ] **Step 1: Write failing tests**

Create `internal/observability/prometheus_test.go`:

```go
package observability

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/JoeRu/federloom/pkg/proto"
)

func scrape(t *testing.T, p *prometheusOutput) string {
	t.Helper()
	w := httptest.NewRecorder()
	promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{}).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(w.Body)
	return string(body)
}

func TestPrometheusOutput_RecordEvent_Counter(t *testing.T) {
	p, err := newPrometheusOutput("", 37.5)
	if err != nil {
		t.Fatalf("newPrometheusOutput: %v", err)
	}
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1"}
	p.recordEvent(e, 50.0, "my-rule", "block")

	body := scrape(t, p)
	if !strings.Contains(body, `federloom_events_received_total{reason="ssh-probe",reporter_id="peer1"} 1`) {
		t.Errorf("missing events counter in:\n%s", body)
	}
	if !strings.Contains(body, `federloom_rules_fired_total{action="block",rule="my-rule"} 1`) {
		t.Errorf("missing rules counter in:\n%s", body)
	}
}

func TestPrometheusOutput_ScoreGauge_AboveThreshold(t *testing.T) {
	p, _ := newPrometheusOutput("", 40.0)
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1"}
	p.recordEvent(e, 50.0, "", "")

	body := scrape(t, p)
	if !strings.Contains(body, `federloom_ip_score{ip="1.2.3.4"} 50`) {
		t.Errorf("expected ip_score gauge above threshold in:\n%s", body)
	}
}

func TestPrometheusOutput_ScoreGauge_BelowThreshold(t *testing.T) {
	p, _ := newPrometheusOutput("", 40.0)
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1"}
	p.recordEvent(e, 30.0, "", "") // below threshold

	body := scrape(t, p)
	if strings.Contains(body, `federloom_ip_score{ip="1.2.3.4"}`) {
		t.Errorf("ip_score should not appear below threshold in:\n%s", body)
	}
}

func TestPrometheusOutput_BlockedGauge(t *testing.T) {
	p, _ := newPrometheusOutput("", 37.5)
	p.blockedIPs.Inc()
	p.blockedIPs.Inc()
	p.blockedIPs.Dec()

	body := scrape(t, p)
	if !strings.Contains(body, "federloom_blocked_ips 1") {
		t.Errorf("expected blocked_ips=1 in:\n%s", body)
	}
}

func TestPrometheusOutput_NoRuleName_SkipsRuleCounter(t *testing.T) {
	p, _ := newPrometheusOutput("", 37.5)
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1"}
	p.recordEvent(e, 50.0, "", "") // no rule matched

	body := scrape(t, p)
	if strings.Contains(body, "federloom_rules_fired_total") {
		t.Errorf("rules counter should not appear when no rule matched in:\n%s", body)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /root/federloom && go test ./internal/observability/... -v
```

Expected: FAIL with "no Go files"

- [ ] **Step 3: Implement prometheus.go**

Create `internal/observability/prometheus.go`:

```go
package observability

import (
	"context"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/JoeRu/federloom/pkg/proto"
)

type prometheusOutput struct {
	events    *prometheus.CounterVec
	rules     *prometheus.CounterVec
	blockedIPs prometheus.Gauge
	score     *prometheus.GaugeVec
	peers     prometheus.Gauge
	federated *prometheus.CounterVec
	registry  *prometheus.Registry
	threshold float64
	addr      string
}

func newPrometheusOutput(addr string, scoreThreshold float64) (*prometheusOutput, error) {
	reg := prometheus.NewRegistry()
	p := &prometheusOutput{
		addr:      addr,
		threshold: scoreThreshold,
		registry:  reg,
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "federloom_events_received_total",
			Help: "Total events processed by the reputation engine.",
		}, []string{"reason", "reporter_id"}),
		rules: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "federloom_rules_fired_total",
			Help: "Total rule evaluations that produced a match.",
		}, []string{"rule", "action"}),
		blockedIPs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "federloom_blocked_ips",
			Help: "Current number of IPs in the enforced block set.",
		}),
		score: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "federloom_ip_score",
			Help: "Current reputation score for IPs at or above the gauge threshold.",
		}, []string{"ip"}),
		peers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "federloom_federation_peers",
			Help: "Number of connected libp2p peers.",
		}),
		federated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "federloom_events_federated_total",
			Help: "Gossip messages exchanged with peers.",
		}, []string{"direction"}),
	}
	for _, c := range []prometheus.Collector{
		p.events, p.rules, p.blockedIPs, p.score, p.peers, p.federated,
	} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *prometheusOutput) start(ctx context.Context) {
	if p.addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: p.addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("observability: prometheus: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
}

func (p *prometheusOutput) recordEvent(e proto.Event, score float64, rule, action string) {
	p.events.WithLabelValues(e.Reason, e.ReporterID).Inc()
	if rule != "" {
		p.rules.WithLabelValues(rule, action).Inc()
	}
	if score >= p.threshold {
		p.score.WithLabelValues(e.IP).Set(score)
	} else {
		p.score.DeleteLabelValues(e.IP)
	}
}
```

- [ ] **Step 4: Run tests**

```bash
cd /root/federloom && go test ./internal/observability/... -v -run TestPrometheus
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add internal/observability/prometheus.go internal/observability/prometheus_test.go go.mod go.sum
git commit -m "feat(observability): Prometheus metrics output"
```

---

## Task 4: SQLite output

**Files:**
- Create: `internal/observability/sqlite.go`
- Create: `internal/observability/sqlite_test.go`
- Modify: `go.mod` (add `modernc.org/sqlite`)

- [ ] **Step 1: Add modernc.org/sqlite dependency**

```bash
cd /root/federloom && go get modernc.org/sqlite@latest
```

- [ ] **Step 2: Write failing tests**

Create `internal/observability/sqlite_test.go`:

```go
package observability

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/federloom/pkg/proto"
	// modernc.org/sqlite driver is registered by sqlite.go (same package)
)

func openTestSQLite(t *testing.T) *sqliteOutput {
	t.Helper()
	sq, err := newSQLiteOutput(
		filepath.Join(t.TempDir(), "test.db"),
		30*24*time.Hour, // retention: 30 days
		7*24*time.Hour,  // halfLife: 1 week
		75.0,            // blockThreshold
	)
	if err != nil {
		t.Fatalf("newSQLiteOutput: %v", err)
	}
	t.Cleanup(func() { sq.db.Close() })
	return sq
}

func TestSQLiteOutput_RecordEvent(t *testing.T) {
	sq := openTestSQLite(t)
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1", SubnetID: "s1"}
	sq.recordEvent(e, 42.0)

	var count int
	sq.db.QueryRow("SELECT COUNT(*) FROM events WHERE ip='1.2.3.4' AND reason='ssh-probe'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 event row, got %d", count)
	}
}

func TestSQLiteOutput_RecordRuleFiring(t *testing.T) {
	sq := openTestSQLite(t)
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1"}
	sq.recordRuleFiring(e, 80.0, "ssh-burst", "block")

	var rule, action string
	sq.db.QueryRow("SELECT rule, action FROM rule_firings WHERE ip='1.2.3.4'").Scan(&rule, &action)
	if rule != "ssh-burst" || action != "block" {
		t.Errorf("rule=%q action=%q, want ssh-burst/block", rule, action)
	}
}

func TestSQLiteOutput_RecordBlock_DueTime_InFuture(t *testing.T) {
	sq := openTestSQLite(t)
	sq.recordBlock("1.2.3.4", 150.0) // score well above threshold

	var expectedUnblock int64
	sq.db.QueryRow("SELECT expected_unblock FROM blocks WHERE ip='1.2.3.4'").Scan(&expectedUnblock)
	if expectedUnblock <= time.Now().Unix() {
		t.Errorf("expected_unblock should be in the future for score > threshold, got %d", expectedUnblock)
	}
}

func TestSQLiteOutput_RecordBlock_AtThreshold_DueTimeNow(t *testing.T) {
	sq := openTestSQLite(t)
	sq.recordBlock("1.2.3.4", 75.0) // exactly at threshold → due now

	var expectedUnblock int64
	sq.db.QueryRow("SELECT expected_unblock FROM blocks WHERE ip='1.2.3.4'").Scan(&expectedUnblock)
	// log2(75/75) = 0, so expected_unblock ≈ blocked_at
	if expectedUnblock > time.Now().Add(5*time.Second).Unix() {
		t.Errorf("score at threshold should produce near-zero due-time, got %d", expectedUnblock)
	}
}

func TestSQLiteOutput_RecordUnblock(t *testing.T) {
	sq := openTestSQLite(t)
	sq.recordBlock("1.2.3.4", 80.0)
	sq.recordUnblock("1.2.3.4")

	var unblockedAt sql.NullInt64
	sq.db.QueryRow("SELECT unblocked_at FROM blocks WHERE ip='1.2.3.4'").Scan(&unblockedAt)
	if !unblockedAt.Valid {
		t.Error("unblocked_at should be set after recordUnblock")
	}
}

func TestSQLiteOutput_RetentionSweep_DeletesOld(t *testing.T) {
	sq := openTestSQLite(t)
	oldTs := time.Now().Add(-60 * 24 * time.Hour).Unix()
	sq.db.Exec("INSERT INTO events(ts,ip,reason,reporter,score) VALUES(?,?,?,?,?)",
		oldTs, "1.2.3.4", "ssh-probe", "peer1", 10.0)
	sq.recordEvent(proto.Event{IP: "5.6.7.8", Reason: "ssh-probe", ReporterID: "peer2"}, 20.0)

	sq.sweep()

	var count int
	sq.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 event after sweep (old deleted), got %d", count)
	}
}

func TestSQLiteOutput_RetentionSweep_KeepsActiveBlocks(t *testing.T) {
	sq := openTestSQLite(t)
	// Insert a block that is old but still active (unblocked_at IS NULL)
	oldTs := time.Now().Add(-60 * 24 * time.Hour).Unix()
	sq.db.Exec("INSERT INTO blocks(ip,blocked_at,score_at_block,expected_unblock) VALUES(?,?,?,?)",
		"1.2.3.4", oldTs, 80.0, oldTs+3600)

	sq.sweep()

	var count int
	sq.db.QueryRow("SELECT COUNT(*) FROM blocks WHERE ip='1.2.3.4' AND unblocked_at IS NULL").Scan(&count)
	if count != 1 {
		t.Errorf("active block should not be pruned by retention sweep")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd /root/federloom && go test ./internal/observability/... -run TestSQLite -v
```

Expected: FAIL with "undefined: newSQLiteOutput"

- [ ] **Step 4: Implement sqlite.go**

Create `internal/observability/sqlite.go`:

```go
package observability

import (
	"context"
	"database/sql"
	"log"
	"math"
	"time"

	"github.com/JoeRu/federloom/pkg/proto"
	_ "modernc.org/sqlite"
)

type sqliteOutput struct {
	db        *sql.DB
	retention time.Duration
	halfLife  time.Duration
	threshold float64
}

func newSQLiteOutput(path string, retention, halfLife time.Duration, threshold float64) (*sqliteOutput, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := initSQLiteSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &sqliteOutput{db: db, retention: retention, halfLife: halfLife, threshold: threshold}, nil
}

func initSQLiteSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id       INTEGER PRIMARY KEY AUTOINCREMENT,
			ts       INTEGER NOT NULL,
			ip       TEXT    NOT NULL,
			reason   TEXT    NOT NULL,
			reporter TEXT    NOT NULL,
			subnet   TEXT    NOT NULL DEFAULT '',
			score    REAL    NOT NULL
		);
		CREATE INDEX IF NOT EXISTS events_ts ON events(ts);

		CREATE TABLE IF NOT EXISTS rule_firings (
			id     INTEGER PRIMARY KEY AUTOINCREMENT,
			ts     INTEGER NOT NULL,
			ip     TEXT    NOT NULL,
			rule   TEXT    NOT NULL,
			action TEXT    NOT NULL,
			score  REAL    NOT NULL
		);
		CREATE INDEX IF NOT EXISTS rule_firings_ts ON rule_firings(ts);

		CREATE TABLE IF NOT EXISTS blocks (
			id               INTEGER PRIMARY KEY AUTOINCREMENT,
			ip               TEXT    NOT NULL,
			blocked_at       INTEGER NOT NULL,
			unblocked_at     INTEGER,
			score_at_block   REAL    NOT NULL,
			expected_unblock INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS blocks_ip ON blocks(ip);
	`)
	return err
}

func (s *sqliteOutput) recordEvent(e proto.Event, score float64) {
	_, err := s.db.Exec(
		`INSERT INTO events(ts,ip,reason,reporter,subnet,score) VALUES(?,?,?,?,?,?)`,
		time.Now().Unix(), e.IP, e.Reason, e.ReporterID, e.SubnetID, score,
	)
	if err != nil {
		log.Printf("observability: sqlite event: %v", err)
	}
}

func (s *sqliteOutput) recordRuleFiring(e proto.Event, score float64, rule, action string) {
	_, err := s.db.Exec(
		`INSERT INTO rule_firings(ts,ip,rule,action,score) VALUES(?,?,?,?,?)`,
		time.Now().Unix(), e.IP, rule, action, score,
	)
	if err != nil {
		log.Printf("observability: sqlite rule_firing: %v", err)
	}
}

func (s *sqliteOutput) recordBlock(ip string, score float64) {
	now := time.Now()
	expectedUnblock := s.computeUnblock(score, now)
	_, err := s.db.Exec(
		`INSERT INTO blocks(ip,blocked_at,score_at_block,expected_unblock) VALUES(?,?,?,?)`,
		ip, now.Unix(), score, expectedUnblock.Unix(),
	)
	if err != nil {
		log.Printf("observability: sqlite block: %v", err)
	}
}

func (s *sqliteOutput) recordUnblock(ip string) {
	_, err := s.db.Exec(
		`UPDATE blocks SET unblocked_at=? WHERE ip=? AND unblocked_at IS NULL`,
		time.Now().Unix(), ip,
	)
	if err != nil {
		log.Printf("observability: sqlite unblock: %v", err)
	}
}

// computeUnblock returns the estimated time when score decays below threshold.
// Formula: t = halfLife × log2(score / threshold).
func (s *sqliteOutput) computeUnblock(score float64, now time.Time) time.Time {
	if score <= s.threshold {
		return now
	}
	nanos := float64(s.halfLife) * math.Log2(score/s.threshold)
	return now.Add(time.Duration(nanos))
}

func (s *sqliteOutput) sweep() {
	cutoff := time.Now().Add(-s.retention).Unix()
	for _, q := range []string{
		`DELETE FROM events       WHERE ts < ?`,
		`DELETE FROM rule_firings WHERE ts < ?`,
		`DELETE FROM blocks       WHERE ts < ? AND unblocked_at IS NOT NULL`,
	} {
		if _, err := s.db.Exec(q, cutoff); err != nil {
			log.Printf("observability: retention sweep: %v", err)
		}
	}
}

func (s *sqliteOutput) startRetentionSweep(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.sweep()
			case <-ctx.Done():
				_ = s.db.Close()
				return
			}
		}
	}()
}
```

(Add `"context"` to the imports in sqlite.go.)

- [ ] **Step 5: Run tests**

```bash
cd /root/federloom && go test ./internal/observability/... -v -run TestSQLite
```

Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add internal/observability/sqlite.go internal/observability/sqlite_test.go go.mod go.sum
git commit -m "feat(observability): SQLite event history with retention sweep"
```

---

## Task 5: Observer core (fan-out)

**Files:**
- Create: `internal/observability/observer.go`

No new tests needed — the Observer is a thin fan-out; both outputs are already covered by Tasks 3 and 4.

- [ ] **Step 1: Implement observer.go**

Create `internal/observability/observer.go`:

```go
package observability

import (
	"context"
	"path/filepath"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/pkg/proto"
)

// Observer fans out observability events to an optional Prometheus output
// and an optional SQLite output. All methods are safe to call on a nil
// *Observer — nil means observability is disabled.
type Observer struct {
	prom *prometheusOutput
	sq   *sqliteOutput
}

// New creates an Observer from cfg. Both outputs are optional; an empty addr
// or path disables that output. Returns nil (not an error) when both are disabled.
func New(cfg config.ObservabilityConfig, repCfg config.ReputationConfig, storeDir string) (*Observer, error) {
	if cfg.PrometheusAddr == "" && cfg.SQLitePath == "" {
		return nil, nil
	}
	o := &Observer{}

	if cfg.PrometheusAddr != "" {
		threshold := cfg.ScoreGaugeThreshold
		if threshold == 0 {
			threshold = repCfg.BlockThreshold / 2
		}
		p, err := newPrometheusOutput(cfg.PrometheusAddr, threshold)
		if err != nil {
			return nil, err
		}
		o.prom = p
	}

	if cfg.SQLitePath != "" {
		path := cfg.SQLitePath
		if !filepath.IsAbs(path) {
			path = filepath.Join(storeDir, path)
		}
		retention := cfg.SQLiteRetention.Duration
		if retention <= 0 {
			retention = 360 * time.Hour
		}
		halfLife := repCfg.HalfLife.Duration
		if halfLife <= 0 {
			halfLife = 7 * 24 * time.Hour
		}
		sq, err := newSQLiteOutput(path, retention, halfLife, repCfg.BlockThreshold)
		if err != nil {
			return nil, err
		}
		o.sq = sq
	}

	return o, nil
}

// Start launches the Prometheus HTTP server and the SQLite retention sweep goroutine.
func (o *Observer) Start(ctx context.Context) {
	if o == nil {
		return
	}
	if o.prom != nil {
		o.prom.start(ctx)
	}
	if o.sq != nil {
		o.sq.startRetentionSweep(ctx)
	}
}

// RecordEvent records a processed ingest event. rule is empty when no rule matched.
func (o *Observer) RecordEvent(e proto.Event, score float64, rule, action string) {
	if o == nil {
		return
	}
	if o.prom != nil {
		o.prom.recordEvent(e, score, rule, action)
	}
	if o.sq != nil {
		o.sq.recordEvent(e, score)
		if rule != "" {
			o.sq.recordRuleFiring(e, score, rule, action)
		}
	}
}

// RecordBlock records that ip was added to the block set at the given score.
func (o *Observer) RecordBlock(ip string, score float64) {
	if o == nil {
		return
	}
	if o.prom != nil {
		o.prom.blockedIPs.Inc()
	}
	if o.sq != nil {
		o.sq.recordBlock(ip, score)
	}
}

// RecordUnblock records that ip was removed from the block set.
func (o *Observer) RecordUnblock(ip string) {
	if o == nil {
		return
	}
	if o.prom != nil {
		o.prom.blockedIPs.Dec()
	}
	if o.sq != nil {
		o.sq.recordUnblock(ip)
	}
}

// UpdatePeers sets the current count of connected libp2p peers.
func (o *Observer) UpdatePeers(n int) {
	if o == nil || o.prom == nil {
		return
	}
	o.prom.peers.Set(float64(n))
}

// RecordFederated increments the gossip message counter. direction is "in" or "out".
func (o *Observer) RecordFederated(direction string) {
	if o == nil || o.prom == nil {
		return
	}
	o.prom.federated.WithLabelValues(direction).Inc()
}
```

- [ ] **Step 2: Build check**

```bash
cd /root/federloom && go build ./internal/observability/...
```

Expected: no errors

- [ ] **Step 3: Run all observability tests**

```bash
cd /root/federloom && go test ./internal/observability/... -v -race
```

Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add internal/observability/observer.go
git commit -m "feat(observability): Observer fan-out wiring Prometheus and SQLite"
```

---

## Task 6: Wire Observer into Node

**Files:**
- Modify: `internal/node/node.go`

- [ ] **Step 1: Add obs field and wire New()**

In `internal/node/node.go`:

Add import:
```go
"github.com/JoeRu/federloom/internal/observability"
```

Add `obs` field to `Node` struct (after `burst`):
```go
obs *observability.Observer
```

In `New()`, add after the `rules.Load(...)` and `rules.NewBurstStore()` lines:

```go
obs, err := observability.New(cfg.Observability, cfg.Reputation, cfg.Store.Dir)
if err != nil {
    return nil, fmt.Errorf("node: observability: %w", err)
}
```

In the `return &Node{...}` block, add:
```go
obs: obs,
```

- [ ] **Step 2: Wire Start in Run()**

At the top of `Run()`, before `n.sink.Start(ctx)`:

```go
n.obs.Start(ctx)
```

Also add the peers ticker in `Run()` after `remoteCh` is set up:

```go
if n.transport != nil {
    go func() {
        t := time.NewTicker(30 * time.Second)
        defer t.Stop()
        for {
            select {
            case <-t.C:
                n.obs.UpdatePeers(len(n.transport.Host().Network().Peers()))
            case <-ctx.Done():
                return
            }
        }
    }()
}
```

And in the `remoteCh` receive case in the select loop:

```go
case re, ok := <-remoteCh:
    if !ok {
        remoteCh = nil
        continue
    }
    n.ProcessRemote(re)
    n.obs.RecordFederated("in")
```

- [ ] **Step 3: Wire processLocal()**

Replace the existing `processLocal` body with:

```go
func (n *Node) processLocal(ctx context.Context, e proto.Event) {
	if n.neverblock.Contains(e.IP) {
		return
	}
	e.ReporterID = n.selfID
	e.Vouch = n.vouch
	if _, err := n.rep.Record(e.IP, e.Reason, n.selfID, 1.0, n.selfID, true); err != nil {
		log.Printf("node: record local %s: %v", e.IP, err)
		return
	}
	n.burst.Record(e.IP, e.Reason, time.Now())
	rec, _ := n.rep.GetRecord(e.IP)
	action, ruleName := n.rules.Evaluate(e, rec, n.burst)
	switch action {
	case rules.ActionBlock:
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		} else {
			n.obs.RecordBlock(e.IP, rec.Score)
		}
	case rules.ActionWatch:
		log.Printf("node: watch %s reason=%s score=%.1f", e.IP, e.Reason, rec.Score)
	}
	n.obs.RecordEvent(e, rec.Score, ruleName, string(action))
	if n.transport != nil {
		if err := n.transport.Publish(ctx, e); err != nil {
			log.Printf("node: publish %s: %v", e.IP, err)
		} else {
			n.obs.RecordFederated("out")
		}
	}
}
```

- [ ] **Step 4: Wire ProcessRemote()**

After the existing `switch n.rules.Evaluate(...)` block in `ProcessRemote`, apply the same pattern:

```go
action, ruleName := n.rules.Evaluate(e, rec, n.burst)
switch action {
case rules.ActionBlock:
    if err := n.sink.Block(e.IP); err != nil {
        log.Printf("node: block %s: %v", e.IP, err)
    } else {
        n.obs.RecordBlock(e.IP, rec.Score)
    }
case rules.ActionWatch:
    log.Printf("node: watch %s reason=%s score=%.1f", e.IP, e.Reason, rec.Score)
}
n.obs.RecordEvent(e, rec.Score, ruleName, string(action))
```

- [ ] **Step 5: Wire runDecay()**

In `runDecay()`, after `n.sink.Unblock(ip)` succeeds:

```go
if score < n.cfg.Reputation.UnblockThreshold {
    if err := n.sink.Unblock(ip); err != nil {
        log.Printf("node: unblock %s: %v", ip, err)
    } else {
        n.obs.RecordUnblock(ip)
    }
}
```

- [ ] **Step 6: Run all tests**

```bash
cd /root/federloom && go test ./... -race
```

Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add internal/node/node.go
git commit -m "feat(node): wire Observer into event pipeline"
```

---

## Task 7: Deploy config updates

**Files:**
- Modify: `deploy/honeypot/config.yaml`
- Modify: `deploy/honeypot/docker-compose.yml`
- Modify: `deploy/mailcow/config.yaml`
- Modify: `deploy/wordpress/config.yaml`
- Modify: `deploy/examples/config.solo.yaml`

- [ ] **Step 1: Update honeypot config (both outputs)**

Add to the end of `deploy/honeypot/config.yaml`:

```yaml
observability:
  prometheus_addr: ":9101"
  sqlite_path: "metrics.db"      # relative to store.dir: /var/lib/federloom/metrics.db
  sqlite_retention: 360h         # 15 days
```

- [ ] **Step 2: Expose port 9101 in honeypot docker-compose**

In `deploy/honeypot/docker-compose.yml`, add `- "9101:9101"` to the federloom service ports:

```yaml
    ports:
      - "7700:7700"
      - "9101:9101"
```

- [ ] **Step 3: Update mailcow config (Prometheus only)**

Add to the end of `deploy/mailcow/config.yaml`:

```yaml
observability:
  prometheus_addr: ":9101"
```

- [ ] **Step 4: Update wordpress config (Prometheus only)**

Add to the end of `deploy/wordpress/config.yaml`:

```yaml
observability:
  prometheus_addr: ":9101"
```

- [ ] **Step 5: Add commented example to config.solo.yaml**

Add to the end of `deploy/examples/config.solo.yaml`:

```yaml
# Optional observability plane (disabled by default, spec §11.2).
# Uncomment to enable:
# observability:
#   prometheus_addr: ":9101"          # expose Prometheus /metrics
#   sqlite_path: "metrics.db"         # event history (relative to store.dir)
#   sqlite_retention: 360h            # prune rows older than 15 days
#   score_gauge_threshold: 0          # emit ip_score gauge for IPs above this; 0 = block_threshold/2
```

- [ ] **Step 6: Build check**

```bash
cd /root/federloom && go build ./...
```

Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add deploy/honeypot/config.yaml deploy/honeypot/docker-compose.yml \
        deploy/mailcow/config.yaml deploy/wordpress/config.yaml \
        deploy/examples/config.solo.yaml
git commit -m "feat(deploy): enable observability in honeypot/mailcow/wordpress configs"
```

---

## Task 8: Grafana dashboard and provisioning files

**Files:**
- Create: `deploy/grafana/federloom-dashboard.json`
- Create: `deploy/grafana/provisioning/dashboards/federloom.yml`
- Create: `deploy/grafana/provisioning/datasources/federloom-sqlite.yml`

- [ ] **Step 1: Create provisioning dashboard pointer**

Create `deploy/grafana/provisioning/dashboards/federloom.yml`:

```yaml
apiVersion: 1
providers:
  - name: FederLoom
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    options:
      path: /etc/grafana/provisioning/dashboards/federloom
```

- [ ] **Step 2: Create SQLite datasource config**

Create `deploy/grafana/provisioning/datasources/federloom-sqlite.yml`:

```yaml
apiVersion: 1
datasources:
  - name: FederLoom SQLite
    type: frser-sqlite-datasource
    access: proxy
    uid: federloom-sqlite
    jsonData:
      path: /var/lib/federloom/metrics.db
    editable: true
```

- [ ] **Step 3: Create the Grafana dashboard JSON**

Create `deploy/grafana/federloom-dashboard.json`:

```json
{
  "__inputs": [
    {
      "name": "DS_PROMETHEUS",
      "label": "Prometheus",
      "type": "datasource",
      "pluginId": "prometheus",
      "pluginName": "Prometheus"
    },
    {
      "name": "DS_FEDERLOOM_SQLITE",
      "label": "FederLoom SQLite",
      "type": "datasource",
      "pluginId": "frser-sqlite-datasource",
      "pluginName": "frser-sqlite-datasource"
    }
  ],
  "__elements": {},
  "__requires": [
    {"type": "grafana", "id": "grafana", "name": "Grafana", "version": "10.0.0"},
    {"type": "datasource", "id": "prometheus", "name": "Prometheus", "version": "1.0.0"},
    {"type": "datasource", "id": "frser-sqlite-datasource", "name": "frser-sqlite-datasource", "version": "1.0.0"},
    {"type": "panel", "id": "timeseries", "name": "Time series", "version": ""},
    {"type": "panel", "id": "stat", "name": "Stat", "version": ""},
    {"type": "panel", "id": "barchart", "name": "Bar chart", "version": ""},
    {"type": "panel", "id": "table", "name": "Table", "version": ""}
  ],
  "annotations": {"list": []},
  "description": "FederLoom reputation events, rule firings, and active blocks with due-time",
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 1,
  "id": null,
  "links": [],
  "panels": [
    {
      "collapsed": false,
      "gridPos": {"h": 1, "w": 24, "x": 0, "y": 0},
      "id": 10,
      "title": "Live — Prometheus",
      "type": "row"
    },
    {
      "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
      "fieldConfig": {
        "defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 1}},
        "overrides": []
      },
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 1},
      "id": 1,
      "options": {"legend": {"calcs": ["sum"], "displayMode": "table"}, "tooltip": {"mode": "multi"}},
      "targets": [
        {
          "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
          "expr": "sum by (reason) (rate(federloom_events_received_total{job=~\"$node\"}[5m]) * 60)",
          "legendFormat": "{{reason}}",
          "refId": "A"
        }
      ],
      "title": "Events / min by reason",
      "type": "timeseries"
    },
    {
      "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
      "fieldConfig": {
        "defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 1}},
        "overrides": []
      },
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 1},
      "id": 2,
      "options": {"legend": {"calcs": ["sum"], "displayMode": "table"}, "tooltip": {"mode": "multi"}},
      "targets": [
        {
          "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
          "expr": "sum by (action) (rate(federloom_rules_fired_total{job=~\"$node\"}[5m]) * 60)",
          "legendFormat": "{{action}}",
          "refId": "A"
        }
      ],
      "title": "Rule firings / min by action",
      "type": "timeseries"
    },
    {
      "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
      "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "thresholds": {"steps": [{"color": "green", "value": null}, {"color": "red", "value": 1}]}}, "overrides": []},
      "gridPos": {"h": 4, "w": 6, "x": 0, "y": 9},
      "id": 3,
      "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "orientation": "auto", "textMode": "auto", "colorMode": "background"},
      "targets": [
        {
          "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
          "expr": "sum(federloom_blocked_ips{job=~\"$node\"})",
          "legendFormat": "Blocked IPs",
          "refId": "A"
        }
      ],
      "title": "Blocked IPs",
      "type": "stat"
    },
    {
      "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
      "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "thresholds": {"steps": [{"color": "blue", "value": null}]}}, "overrides": []},
      "gridPos": {"h": 4, "w": 6, "x": 6, "y": 9},
      "id": 4,
      "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "orientation": "auto", "textMode": "auto", "colorMode": "background"},
      "targets": [
        {
          "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
          "expr": "sum(federloom_federation_peers{job=~\"$node\"})",
          "legendFormat": "Peers",
          "refId": "A"
        }
      ],
      "title": "Federation peers",
      "type": "stat"
    },
    {
      "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
      "fieldConfig": {"defaults": {}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 9},
      "id": 5,
      "options": {"xField": "Value", "orientation": "horizontal"},
      "targets": [
        {
          "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
          "expr": "topk(10, sum by (reporter_id) (federloom_events_received_total{job=~\"$node\"}))",
          "legendFormat": "{{reporter_id}}",
          "instant": true,
          "refId": "A"
        }
      ],
      "title": "Top 10 reporters",
      "type": "barchart"
    },
    {
      "collapsed": false,
      "gridPos": {"h": 1, "w": 24, "x": 0, "y": 17},
      "id": 11,
      "title": "History — SQLite (local node only)",
      "type": "row"
    },
    {
      "datasource": {"type": "frser-sqlite-datasource", "uid": "${DS_FEDERLOOM_SQLITE}"},
      "fieldConfig": {"defaults": {}, "overrides": []},
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 18},
      "id": 6,
      "options": {"sortBy": [{"displayName": "time", "desc": true}]},
      "targets": [
        {
          "datasource": {"type": "frser-sqlite-datasource", "uid": "${DS_FEDERLOOM_SQLITE}"},
          "rawSql": "SELECT datetime(ts,'unixepoch','localtime') AS time, ip, reason, reporter, ROUND(score,1) AS score FROM events ORDER BY ts DESC LIMIT 200",
          "format": "table",
          "refId": "A"
        }
      ],
      "title": "Event log (latest 200)",
      "type": "table"
    },
    {
      "datasource": {"type": "frser-sqlite-datasource", "uid": "${DS_FEDERLOOM_SQLITE}"},
      "fieldConfig": {"defaults": {}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 26},
      "id": 7,
      "options": {"sortBy": [{"displayName": "due_time", "desc": false}]},
      "targets": [
        {
          "datasource": {"type": "frser-sqlite-datasource", "uid": "${DS_FEDERLOOM_SQLITE}"},
          "rawSql": "SELECT ip, ROUND(score_at_block,1) AS score, datetime(expected_unblock,'unixepoch','localtime') AS due_time FROM blocks WHERE unblocked_at IS NULL ORDER BY expected_unblock ASC",
          "format": "table",
          "refId": "A"
        }
      ],
      "title": "Active blocks + due-time",
      "type": "table"
    },
    {
      "datasource": {"type": "frser-sqlite-datasource", "uid": "${DS_FEDERLOOM_SQLITE}"},
      "fieldConfig": {"defaults": {}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 26},
      "id": 8,
      "options": {"sortBy": [{"displayName": "time", "desc": true}]},
      "targets": [
        {
          "datasource": {"type": "frser-sqlite-datasource", "uid": "${DS_FEDERLOOM_SQLITE}"},
          "rawSql": "SELECT datetime(ts,'unixepoch','localtime') AS time, ip, rule, action, ROUND(score,1) AS score FROM rule_firings ORDER BY ts DESC LIMIT 200",
          "format": "table",
          "refId": "A"
        }
      ],
      "title": "Rule firings (latest 200)",
      "type": "table"
    }
  ],
  "schemaVersion": 39,
  "tags": ["federloom"],
  "templating": {
    "list": [
      {
        "current": {"selected": true, "text": "All", "value": "$__all"},
        "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
        "definition": "label_values(federloom_events_received_total,job)",
        "hide": 0,
        "includeAll": true,
        "label": "Node",
        "multi": false,
        "name": "node",
        "options": [],
        "query": {
          "query": "label_values(federloom_events_received_total,job)",
          "refId": "StandardVariableQuery"
        },
        "refresh": 1,
        "regex": "",
        "sort": 1,
        "type": "query"
      }
    ]
  },
  "time": {"from": "now-6h", "to": "now"},
  "timepicker": {},
  "timezone": "browser",
  "title": "FederLoom",
  "uid": "federloom-v1",
  "version": 1,
  "weekStart": ""
}
```

- [ ] **Step 4: Commit**

```bash
mkdir -p deploy/grafana/provisioning/dashboards deploy/grafana/provisioning/datasources
git add deploy/grafana/
git commit -m "feat(grafana): dashboard JSON and provisioning files"
```

---

## Task 9: Infrastructure wiring + CHANGELOG

**Files:**
- Modify: `/container/compose/grafana/docker-compose.yml`
- Modify: `/container/compose/prometheus/prometheus.yml`
- Modify: `CHANGELOG.md`

These files are outside the repo (infra config on this machine). Changes are committed to the repo in the CHANGELOG; the infra files are edited in-place.

- [ ] **Step 1: Add volume mounts to Grafana compose**

In `/container/compose/grafana/docker-compose.yml`, add two items to the `grafana` service `volumes:` list:

```yaml
     - federloom-data:/var/lib/federloom:ro
     - /root/federloom/deploy/grafana/provisioning/dashboards:/etc/grafana/provisioning/dashboards/federloom:ro
     - /root/federloom/deploy/grafana/provisioning/datasources:/etc/grafana/provisioning/datasources/federloom:ro
```

At the bottom of the file, declare the external volume so Docker Compose can reference the FederLoom named volume:

```yaml
volumes:
  grafana-storage:
    external: true
  federloom-data:
    external: true
```

- [ ] **Step 2: Add federloom scrape jobs to Prometheus**

In `/container/compose/prometheus/prometheus.yml`, add three jobs at the end of `scrape_configs:`:

```yaml
  - job_name: "federloom-honeypot"
    scrape_interval: "30s"
    static_configs:
      - targets: ['host.docker.internal:9101']
        labels:
          node: honeypot

  - job_name: "federloom-mailcow"
    scrape_interval: "30s"
    static_configs:
      - targets: ['100.120.31.14:9101']
        labels:
          node: mailcow

  - job_name: "federloom-wordpress"
    scrape_interval: "30s"
    static_configs:
      - targets: ['100.92.58.24:9101']
        labels:
          node: wordpress
```

- [ ] **Step 3: Reload Prometheus and Grafana**

```bash
docker exec prometheus kill -HUP 1
docker compose -f /container/compose/grafana/docker-compose.yml up -d grafana
```

- [ ] **Step 4: Verify Prometheus targets**

Open `http://prometheus.joesnuc:9099/targets` and confirm `federloom-honeypot` appears (mailcow and wordpress will show DOWN until their FederLoom containers are rebuilt with the new image).

- [ ] **Step 5: Add CHANGELOG entry**

In `CHANGELOG.md`, add under `## [Unreleased]`:

```markdown
### Added
- `internal/observability`: dual-output Observer — Prometheus `/metrics` (port 9101) + SQLite
  event history with configurable retention (default 15 days). Both disabled by default.
- Six Prometheus metrics: `federloom_events_received_total`, `federloom_rules_fired_total`,
  `federloom_blocked_ips`, `federloom_ip_score`, `federloom_federation_peers`,
  `federloom_events_federated_total`.
- SQLite tables: `events`, `rule_firings`, `blocks` with precomputed `expected_unblock`
  (due-time for active blocks).
- `deploy/grafana/federloom-dashboard.json`: importable Grafana dashboard covering live
  Prometheus panels and local SQLite history panels.
- `rules.Evaluate` now returns `(Action, string)` — matched rule name available for metrics.
- Honeypot, mailcow, and wordpress deploy configs updated to enable observability.

### Changed
- `internal/rules`: `Evaluate` signature changed to `(Action, string)`.
```

- [ ] **Step 6: Run full test suite one final time**

```bash
cd /root/federloom && go test ./... -race
```

Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add CHANGELOG.md
git commit -m "feat(observability): complete Grafana dashboard, infra wiring, and CHANGELOG"
```
