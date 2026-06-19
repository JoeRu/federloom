# Blocklist Effectiveness Monitoring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-rule effectiveness metrics (blocks, latency, corroboration, recurrence) to SwarmGuard's Prometheus output, a textfile exporter for cross-system metrics, and an on-demand CLI effectiveness report for the WordPress node.

**Architecture:** Three independent deliverables sharing the same `{rule}` label namespace: (1) new native Go Prometheus metrics emitted at block/unblock time in `internal/observability/`; (2) a cron-driven bash textfile exporter querying SQLite + CrowdSec; (3) an on-demand bash CLI report with nginx log correlation. The Go changes extend the existing `Observer.RecordBlock`/`RecordUnblock` signatures to thread rule context through.

**Tech Stack:** Go 1.25 (`prometheus/client_golang` histograms), bash + sqlite3 + jq (NixOS node_exporter textfile), `docker exec` for nginx log + CrowdSec access.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `internal/observability/prometheus.go` | Modify | Add 5 new metric definitions + 3 recording methods |
| `internal/observability/prometheus_test.go` | Modify | Tests for the 5 new metrics |
| `internal/observability/observer.go` | Modify | Update `RecordBlock` signature, add rule-tracking maps, recurrence logic |
| `internal/node/node.go` | Modify | Update 2 `RecordBlock` call sites to pass rule + firstSeen + corroboration |
| `deploy/wordpress/config.yaml` | Modify | Add `sqlite_path` + `sqlite_retention` to observability section |
| `deploy/wordpress/swarmguard-exporter.sh` | Create | Textfile exporter: SQLite + CrowdSec → node_exporter prom file |
| `deploy/wordpress/effectiveness-report.sh` | Create | CLI on-demand report with nginx log correlation |

---

## Task 1: New effectiveness metrics in prometheus.go

**Files:**
- Modify: `internal/observability/prometheus.go`
- Modify: `internal/observability/prometheus_test.go`

Context: `prometheusOutput` in `prometheus.go` holds all metric definitions. The struct currently has 6 fields. We add 5 more and 3 new recording methods. The existing `recordEvent` method stays unchanged.

- [ ] **Step 1: Write failing tests for the 5 new metrics**

Add to `internal/observability/prometheus_test.go` after `TestPrometheusOutput_NoRuleName_SkipsRuleCounter`:

```go
func TestPrometheusOutput_RecordBlock_EmitsCounterAndHistograms(t *testing.T) {
	p, _ := newPrometheusOutput("", 37.5)
	firstSeen := time.Now().Add(-5 * time.Minute)
	p.recordBlock("ssh-burst", firstSeen, 3)

	body := scrape(t, p)
	if !strings.Contains(body, `swarmguard_blocks_total{rule="ssh-burst"} 1`) {
		t.Errorf("missing blocks_total in:\n%s", body)
	}
	if !strings.Contains(body, `swarmguard_time_to_block_seconds_count{rule="ssh-burst"} 1`) {
		t.Errorf("missing time_to_block histogram in:\n%s", body)
	}
	if !strings.Contains(body, `swarmguard_corroboration_at_block_count{rule="ssh-burst"} 1`) {
		t.Errorf("missing corroboration histogram in:\n%s", body)
	}
}

func TestPrometheusOutput_RecordUnblock_EmitsCounter(t *testing.T) {
	p, _ := newPrometheusOutput("", 37.5)
	p.recordUnblock("http-probe-consensus")

	body := scrape(t, p)
	if !strings.Contains(body, `swarmguard_unblocks_total{rule="http-probe-consensus"} 1`) {
		t.Errorf("missing unblocks_total in:\n%s", body)
	}
}

func TestPrometheusOutput_RecordRecurrence_EmitsCounter(t *testing.T) {
	p, _ := newPrometheusOutput("", 37.5)
	p.recordRecurrence("score-fallback")

	body := scrape(t, p)
	if !strings.Contains(body, `swarmguard_block_recurrence_total{rule="score-fallback"} 1`) {
		t.Errorf("missing block_recurrence_total in:\n%s", body)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /root/swarmguard
go test ./internal/observability/ -run "TestPrometheusOutput_RecordBlock_EmitsCounterAndHistograms|TestPrometheusOutput_RecordUnblock_EmitsCounter|TestPrometheusOutput_RecordRecurrence_EmitsCounter" -v
```

Expected: FAIL — `p.recordBlock`, `p.recordUnblock`, `p.recordRecurrence` undefined.

- [ ] **Step 3: Add 5 metric fields to the `prometheusOutput` struct**

In `internal/observability/prometheus.go`, extend the struct and `newPrometheusOutput` function:

Replace the struct definition with:
```go
type prometheusOutput struct {
	events       *prometheus.CounterVec
	rules        *prometheus.CounterVec
	blockedIPs   prometheus.Gauge
	score        *prometheus.GaugeVec
	peers        prometheus.Gauge
	federated    *prometheus.CounterVec
	blocks       *prometheus.CounterVec
	timeToBlock  *prometheus.HistogramVec
	corroboration *prometheus.HistogramVec
	unblocks     *prometheus.CounterVec
	recurrences  *prometheus.CounterVec
	registry     *prometheus.Registry
	threshold    float64
	addr         string
}
```

In `newPrometheusOutput`, add to the struct literal (after the `federated` field):
```go
		blocks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "swarmguard_blocks_total",
			Help: "Total IPs moved into the block set, by rule.",
		}, []string{"rule"}),
		timeToBlock: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "swarmguard_time_to_block_seconds",
			Help:    "Duration from first event to block decision, by rule.",
			Buckets: []float64{0, 30, 60, 120, 300, 600, 1800, 3600, 14400},
		}, []string{"rule"}),
		corroboration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "swarmguard_corroboration_at_block",
			Help:    "Number of distinct reporters at block time, by rule.",
			Buckets: []float64{1, 2, 3, 4, 5, 10},
		}, []string{"rule"}),
		unblocks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "swarmguard_unblocks_total",
			Help: "Total IPs removed from the block set by score decay, by rule.",
		}, []string{"rule"}),
		recurrences: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "swarmguard_block_recurrence_total",
			Help: "Previously-unblocked IPs re-blocked within 7 days, by original rule.",
		}, []string{"rule"}),
```

Extend the registration loop:
```go
	for _, c := range []prometheus.Collector{
		p.events, p.rules, p.blockedIPs, p.score, p.peers, p.federated,
		p.blocks, p.timeToBlock, p.corroboration, p.unblocks, p.recurrences,
	} {
```

- [ ] **Step 4: Add the 3 recording methods**

Add after `recordEvent` in `prometheus.go`:
```go
func (p *prometheusOutput) recordBlock(rule string, firstSeen time.Time, corroboration int) {
	p.blocks.WithLabelValues(rule).Inc()
	p.timeToBlock.WithLabelValues(rule).Observe(time.Since(firstSeen).Seconds())
	p.corroboration.WithLabelValues(rule).Observe(float64(corroboration))
}

func (p *prometheusOutput) recordUnblock(rule string) {
	p.unblocks.WithLabelValues(rule).Inc()
}

func (p *prometheusOutput) recordRecurrence(rule string) {
	p.recurrences.WithLabelValues(rule).Inc()
}
```

Add `"time"` to the import block if not already present (it is — used by `recordEvent`).

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /root/swarmguard
go test ./internal/observability/ -v
```

Expected: all tests PASS, including the 3 new ones.

- [ ] **Step 6: Commit**

```bash
git add internal/observability/prometheus.go internal/observability/prometheus_test.go
git commit -m "feat(observability): add per-rule effectiveness metrics to Prometheus output

Adds swarmguard_blocks_total, time_to_block_seconds, corroboration_at_block,
unblocks_total, block_recurrence_total — all labeled by rule for tuning decisions.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 2: Thread rule context through the Observer

**Files:**
- Modify: `internal/observability/observer.go`

Context: `Observer.RecordBlock` currently takes `(ip string, score float64)`. We upgrade it to `(ip, rule string, score float64, firstSeen time.Time, corroboration int)` so it can emit the new Prometheus metrics and track which rule blocked each IP (needed for `RecordUnblock` to emit the correct `{rule}` label). The `blockedSet map[string]struct{}` becomes `blockedByRule map[string]string`.

- [ ] **Step 1: Write failing tests for the new Observer behavior**

Add a new file `internal/observability/observer_test.go`:

```go
package observability

import (
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

func newTestObserver(t *testing.T) *Observer {
	t.Helper()
	cfg := config.ObservabilityConfig{PrometheusAddr: ""}
	repCfg := config.ReputationConfig{BlockThreshold: 75}
	o, err := New(cfg, repCfg, t.TempDir())
	if err != nil {
		t.Fatalf("New observer: %v", err)
	}
	// Observer may be nil when both outputs disabled — create a minimal one for testing
	if o == nil {
		o = &Observer{
			blockedByRule:     make(map[string]string),
			recentlyUnblocked: make(map[string]unblockedEntry),
		}
	}
	return o
}

func TestObserver_RecordBlock_IdempotentGauge(t *testing.T) {
	// Second RecordBlock for same IP must not double-count.
	o := newTestObserver(t)
	first := time.Now().Add(-2 * time.Minute)
	o.RecordBlock("1.2.3.4", "ssh-burst", 80.0, first, 2)
	o.RecordBlock("1.2.3.4", "ssh-burst", 85.0, first, 3) // duplicate

	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.blockedByRule) != 1 {
		t.Errorf("expected 1 entry in blockedByRule, got %d", len(o.blockedByRule))
	}
}

func TestObserver_RecordUnblock_TracksRule(t *testing.T) {
	// RecordUnblock should populate recentlyUnblocked with the rule from RecordBlock.
	o := newTestObserver(t)
	o.RecordBlock("1.2.3.4", "http-probe-consensus", 80.0, time.Now().Add(-1*time.Minute), 2)
	o.RecordUnblock("1.2.3.4")

	o.mu.Lock()
	defer o.mu.Unlock()
	entry, ok := o.recentlyUnblocked["1.2.3.4"]
	if !ok {
		t.Fatal("expected entry in recentlyUnblocked after RecordUnblock")
	}
	if entry.rule != "http-probe-consensus" {
		t.Errorf("rule = %q, want http-probe-consensus", entry.rule)
	}
}

func TestObserver_Recurrence_DetectedOnReblock(t *testing.T) {
	// Block → Unblock → Re-block within 7 days: must add to recentlyUnblocked
	// and RecordBlock must detect the recurrence.
	o := newTestObserver(t)
	first := time.Now().Add(-3 * time.Minute)
	o.RecordBlock("1.2.3.4", "score-fallback", 80.0, first, 1)
	o.RecordUnblock("1.2.3.4")

	// Re-block the same IP (simulates it coming back)
	o.RecordBlock("1.2.3.4", "score-fallback", 90.0, time.Now().Add(-30*time.Second), 2)

	o.mu.Lock()
	defer o.mu.Unlock()
	// After re-block, recentlyUnblocked should be cleared for this IP
	if _, still := o.recentlyUnblocked["1.2.3.4"]; still {
		t.Error("expected recentlyUnblocked to be cleared after re-block")
	}
}

func TestObserver_NilSafe(t *testing.T) {
	var o *Observer
	// All methods must be no-ops on nil receiver.
	e := proto.Event{IP: "1.2.3.4", Reason: "test", ReporterID: "p1"}
	o.RecordEvent(e, 50.0, "rule", "block")
	o.RecordBlock("1.2.3.4", "rule", 80.0, time.Now(), 1)
	o.RecordUnblock("1.2.3.4")
	o.UpdatePeers(3)
	o.RecordFederated("out")
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /root/swarmguard
go test ./internal/observability/ -run "TestObserver_" -v
```

Expected: compile error — `RecordBlock` wrong arity, `unblockedEntry` undefined.

- [ ] **Step 3: Rewrite observer.go with new types and signatures**

Replace the full contents of `internal/observability/observer.go`:

```go
package observability

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

type unblockedEntry struct {
	rule        string
	unblockedAt time.Time
}

// Observer fans out observability events to an optional Prometheus output
// and an optional SQLite output. All methods are safe to call on a nil
// *Observer — nil means observability is disabled.
type Observer struct {
	prom              *prometheusOutput
	sq                *sqliteOutput
	mu                sync.Mutex
	blockedByRule     map[string]string       // ip → rule that caused the block
	recentlyUnblocked map[string]unblockedEntry // ip → rule+time; pruned after 7 days
}

// New creates an Observer from cfg. Both outputs are optional; an empty addr
// or path disables that output. Returns nil (not an error) when both are disabled.
func New(cfg config.ObservabilityConfig, repCfg config.ReputationConfig, storeDir string) (*Observer, error) {
	if cfg.PrometheusAddr == "" && cfg.SQLitePath == "" {
		return nil, nil
	}
	o := &Observer{
		blockedByRule:     make(map[string]string),
		recentlyUnblocked: make(map[string]unblockedEntry),
	}

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

// RecordBlock records that ip was added to the block set.
// rule is the rule name that triggered the block.
// firstSeen is when the IP was first observed (used to compute time-to-block latency).
// corroboration is the number of distinct reporters at block time.
// Duplicate calls for the same IP are ignored so the gauge stays accurate.
func (o *Observer) RecordBlock(ip, rule string, score float64, firstSeen time.Time, corroboration int) {
	if o == nil {
		return
	}
	o.mu.Lock()
	_, already := o.blockedByRule[ip]
	if !already {
		o.blockedByRule[ip] = rule
	}
	prev, wasUnblocked := o.recentlyUnblocked[ip]
	if wasUnblocked {
		delete(o.recentlyUnblocked, ip)
	}
	o.mu.Unlock()

	if !already {
		if o.prom != nil {
			o.prom.blockedIPs.Inc()
			o.prom.recordBlock(rule, firstSeen, corroboration)
		}
		if o.sq != nil {
			o.sq.recordBlock(ip, score)
		}
	}
	if wasUnblocked && time.Since(prev.unblockedAt) < 7*24*time.Hour {
		if o.prom != nil {
			o.prom.recordRecurrence(prev.rule)
		}
	}
}

// RecordUnblock records that ip was removed from the block set.
func (o *Observer) RecordUnblock(ip string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	rule, was := o.blockedByRule[ip]
	if was {
		delete(o.blockedByRule, ip)
		o.recentlyUnblocked[ip] = unblockedEntry{rule: rule, unblockedAt: time.Now()}
		// Prune entries older than 7 days to prevent unbounded map growth.
		for k, v := range o.recentlyUnblocked {
			if time.Since(v.unblockedAt) > 7*24*time.Hour {
				delete(o.recentlyUnblocked, k)
			}
		}
	}
	o.mu.Unlock()

	if was {
		if o.prom != nil {
			o.prom.blockedIPs.Dec()
			o.prom.recordUnblock(rule)
		}
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

- [ ] **Step 4: Run all observability tests**

```bash
cd /root/swarmguard
go test ./internal/observability/ -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/observability/observer.go internal/observability/observer_test.go
git commit -m "feat(observability): thread rule context through Observer block/unblock

RecordBlock now accepts rule, firstSeen, corroboration for per-rule metrics.
RecordUnblock looks up the original rule from blockedByRule map.
Recurrence detection: re-blocked IPs within 7 days emit block_recurrence_total.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 3: Update node.go call sites

**Files:**
- Modify: `internal/node/node.go`

Context: Two `RecordBlock` calls in node.go (one in `processLocal`, one in `ProcessRemote`) need the updated signature. Both already have `ruleName` from `n.rules.Evaluate(...)` and `rec` from `n.rep.GetRecord(...)`, so `rec.FirstSeen` and `rec.Corroboration` are directly available. The `RecordUnblock` call in `runDecay` needs no change.

- [ ] **Step 1: Update the two RecordBlock calls**

In `internal/node/node.go`, in `processLocal` (around line 216):
```go
// Old:
n.obs.RecordBlock(e.IP, rec.Score)
// New:
n.obs.RecordBlock(e.IP, ruleName, rec.Score, rec.FirstSeen, rec.Corroboration)
```

In `ProcessRemote` (around line 276):
```go
// Old:
n.obs.RecordBlock(e.IP, rec.Score)
// New:
n.obs.RecordBlock(e.IP, ruleName, rec.Score, rec.FirstSeen, rec.Corroboration)
```

`runDecay` at line 296 stays unchanged: `n.obs.RecordUnblock(ip)`.

- [ ] **Step 2: Build and test**

```bash
cd /root/swarmguard
make build
make test
```

Expected: build succeeds, all tests pass. The adversarial suite exercises block/unblock paths.

- [ ] **Step 3: Commit**

```bash
git add internal/node/node.go
git commit -m "feat(node): pass rule+firstSeen+corroboration to RecordBlock

Wires the new per-rule effectiveness metrics through the block decision
paths in processLocal and ProcessRemote.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 4: Enable SQLite on WordPress + deploy

**Files:**
- Modify: `deploy/wordpress/config.yaml`

Context: The WordPress node currently has no `sqlite_path` in its observability config, so `metrics.db` is never created. Without it the textfile exporter and CLI report have no data to query.

- [ ] **Step 1: Add SQLite config to deploy/wordpress/config.yaml**

Edit the `observability` block in `deploy/wordpress/config.yaml`:

```yaml
observability:
  prometheus_addr: ":9101"
  sqlite_path: "metrics.db"
  sqlite_retention: "720h"   # 30 days
```

- [ ] **Step 2: Deploy to wordpress node**

```bash
/swarmguard-env wordpress
```

Expected output ends with: `==> [wordpress] waiting for metrics endpoint. OK`

- [ ] **Step 3: Verify metrics.db is created**

```bash
ssh -p 2222 root@d.jru.me \
  "ls -lh /var/lib/docker/volumes/wordpress_swarmguard-data/_data/metrics.db"
```

Expected: file exists, size > 0 (events start accumulating immediately from CrowdSec ingest).

- [ ] **Step 4: Commit**

```bash
git add deploy/wordpress/config.yaml
git commit -m "feat(wordpress): enable SQLite observability

Adds sqlite_path and 30-day retention to the wordpress node config
so metrics.db accumulates events for the effectiveness exporter and
CLI report.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 5: Set up node_exporter textfile directory on WordPress

**Context:** node_exporter on wordpress runs from `/opt/node-exporter/docker-compose.yml` (not in the swarmguard repo). It currently mounts only its config file. We need to: (1) install sqlite3 + jq on the host, (2) add a textfile directory mount, (3) add `--collector.textfile.directory` flag to node_exporter.

This task makes changes directly on the WordPress server.

- [ ] **Step 1: Install sqlite3 and jq on wordpress via nix-env**

```bash
ssh -p 2222 root@d.jru.me \
  "nix-env -iA nixpkgs.sqlite nixpkgs.jq"
```

Verify:
```bash
ssh -p 2222 root@d.jru.me "sqlite3 --version && jq --version"
```

Expected: `3.x.x` and `jq-1.x`.

- [ ] **Step 2: Create the textfile directory**

```bash
ssh -p 2222 root@d.jru.me "mkdir -p /var/lib/node_exporter/textfile"
```

- [ ] **Step 3: Update node_exporter docker-compose on wordpress**

```bash
ssh -p 2222 root@d.jru.me "cat /opt/node-exporter/docker-compose.yml"
```

Edit `/opt/node-exporter/docker-compose.yml` on the server to add the textfile mount and flag:

```yaml
services:
  node_exporter:
    image: quay.io/prometheus/node-exporter:latest
    container_name: node_exporter
    command:
      - "--path.rootfs=/host"
      - "--web.config.file=/etc/prometheus/web.yml"
      - "--collector.textfile.directory=/var/lib/node_exporter/textfile"
    ports:
      - 9100:9100
    pid: host
    restart: unless-stopped
    volumes:
      - '/:/host:ro,rslave'
      - ./config/web.yml:/etc/prometheus/web.yml
      - /var/lib/node_exporter/textfile:/var/lib/node_exporter/textfile:ro
```

Apply with:
```bash
ssh -p 2222 root@d.jru.me \
  "cd /opt/node-exporter && docker compose up -d"
```

- [ ] **Step 4: Verify textfile collector is active**

```bash
ssh -p 2222 root@d.jru.me \
  "docker exec node_exporter /bin/node_exporter --help 2>&1 | grep textfile || true"
```

Then write a test metric and check it scrapes:
```bash
ssh -p 2222 root@d.jru.me "
  echo '# HELP test_metric Test\n# TYPE test_metric gauge\ntest_metric 1' \
    > /var/lib/node_exporter/textfile/test.prom
  sleep 2
  curl -s http://localhost:9100/metrics | grep test_metric
  rm /var/lib/node_exporter/textfile/test.prom
"
```

Expected: `test_metric 1` appears in curl output.

---

## Task 6: Textfile exporter script

**Files:**
- Create: `deploy/wordpress/swarmguard-exporter.sh`

Context: Runs every 5 minutes via cron on the WordPress server. Queries SwarmGuard's `metrics.db` and CrowdSec to emit cross-system effectiveness metrics. Uses a rolling 24h window. Writes atomically to `/var/lib/node_exporter/textfile/swarmguard_effectiveness.prom`.

- [ ] **Step 1: Create the exporter script**

Create `deploy/wordpress/swarmguard-exporter.sh`:

```bash
#!/usr/bin/env bash
# swarmguard-exporter.sh — textfile exporter for node_exporter (5-min cron)
# Queries SwarmGuard SQLite + CrowdSec and writes effectiveness metrics.
set -euo pipefail

SQLITE_DB="/var/lib/docker/volumes/wordpress_swarmguard-data/_data/metrics.db"
NGINX_CTR="wordpress_docker_stack-nginx_webmail-1"
CROWDSEC_CTR="crowdsec"
OUTDIR="/var/lib/node_exporter/textfile"
OUTFILE="$OUTDIR/swarmguard_effectiveness.prom"
TMPFILE="$OUTFILE.tmp"
WINDOW_HOURS=24

SINCE=$(date -d "$WINDOW_HOURS hours ago" +%s)

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
" | awk -F'|' '{print "swarmguard_blocks_single_source_total{rule=\""$1"\"} "$2}')

# ── Slip-through: nginx IPs that are also in the block list ──────────────────
# Approximate: intersection of nginx source IPs and currently-blocked IPs.
nginx_ips=$(docker exec "$NGINX_CTR" cat /var/log/nginx/access.log 2>/dev/null \
  | awk '{print $1}' | sort -u) || nginx_ips=""

blocked_ips=$(q "SELECT DISTINCT ip FROM blocks WHERE blocked_at >= $SINCE AND unblocked_at IS NULL;")

if [[ -n "$nginx_ips" && -n "$blocked_ips" ]]; then
  slip_count=$(comm -12 \
    <(echo "$nginx_ips") \
    <(echo "$blocked_ips" | sort) | wc -l | tr -d ' ')
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
}')

# ── CrowdSec overlap ──────────────────────────────────────────────────────────
cs_decisions=$(docker exec "$CROWDSEC_CTR" \
  cscli decisions list -o json --since "${WINDOW_HOURS}h" 2>/dev/null \
  | jq -r '.[].value // empty' 2>/dev/null | sort -u) || cs_decisions=""

swarm_blocked=$(q "SELECT DISTINCT ip FROM blocks WHERE blocked_at >= $SINCE AND unblocked_at IS NULL;" | sort)

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
```

- [ ] **Step 2: Make executable and test manually on wordpress**

```bash
git add deploy/wordpress/swarmguard-exporter.sh
chmod +x deploy/wordpress/swarmguard-exporter.sh
```

Copy and run on wordpress:
```bash
rsync -az deploy/wordpress/swarmguard-exporter.sh root@d.jru.me:/opt/swarmguard/deploy/wordpress/
ssh -p 2222 root@d.jru.me "/opt/swarmguard/deploy/wordpress/swarmguard-exporter.sh"
```

Verify output:
```bash
ssh -p 2222 root@d.jru.me "cat /var/lib/node_exporter/textfile/swarmguard_effectiveness.prom"
```

Expected: file with correct metric lines, no bash errors.

- [ ] **Step 3: Verify node_exporter exposes the metrics**

```bash
ssh -p 2222 root@d.jru.me \
  "curl -s http://localhost:9100/metrics | grep swarmguard_"
```

Expected: all 6 metric families appear.

- [ ] **Step 4: Install cron on wordpress**

```bash
ssh -p 2222 root@d.jru.me "
  (crontab -l; echo '*/5 * * * * /opt/swarmguard/deploy/wordpress/swarmguard-exporter.sh >> /var/log/swarmguard-exporter.log 2>&1') | crontab -
  crontab -l
"
```

Expected: new cron line visible in output.

- [ ] **Step 5: Commit**

```bash
git add deploy/wordpress/swarmguard-exporter.sh
git commit -m "feat(wordpress): add Prometheus textfile exporter for effectiveness metrics

Emits per-rule single-source blocks, nginx slip-through (approximate),
recurrence ratio, and CrowdSec overlap metrics every 5 minutes via cron.
Requires sqlite3 + jq on host (installed via nix-env in Task 5 setup).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 7: CLI effectiveness report script

**Files:**
- Create: `deploy/wordpress/effectiveness-report.sh`

Context: On-demand report that runs directly on the wordpress server. Queries SQLite with exact time windows, parses nginx logs for precise slip-through timing (not just IP overlap), and calls CrowdSec for geo/scenario enrichment. Designed to run as root (same user that can `docker exec`).

- [ ] **Step 1: Create the report script**

Create `deploy/wordpress/effectiveness-report.sh`:

```bash
#!/usr/bin/env bash
# effectiveness-report.sh — on-demand SwarmGuard effectiveness report
# Run directly on the WordPress server.
# Usage: ./effectiveness-report.sh [--hours N | --days N | --since YYYY-MM-DD]
set -euo pipefail

SQLITE_DB="/var/lib/docker/volumes/wordpress_swarmguard-data/_data/metrics.db"
NGINX_CTR="wordpress_docker_stack-nginx_webmail-1"
CROWDSEC_CTR="crowdsec"

# ── Parse arguments ───────────────────────────────────────────────────────────
SINCE_EPOCH=""
WINDOW_LABEL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hours)
      SINCE_EPOCH=$(date -d "$2 hours ago" +%s)
      WINDOW_LABEL="last ${2}h"
      shift 2 ;;
    --days)
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

echo "=== SwarmGuard Effectiveness Report ==="
echo "Node: wordpress  |  Window: $SINCE_HR → $NOW_HR ($WINDOW_LABEL)"
echo ""

# ── Coverage ──────────────────────────────────────────────────────────────────
total_blocked=$(q "SELECT COUNT(DISTINCT ip) FROM blocks WHERE blocked_at >= $SINCE_EPOCH;")

# Get nginx access log IPs with parsed timestamps (field1=ip, rest=log line)
# nginx timestamp format: [16/Jun/2026:14:29:12 +0000]
nginx_log=$(docker exec "$NGINX_CTR" cat /var/log/nginx/access.log 2>/dev/null) || nginx_log=""

# Build temp file: ip<TAB>epoch_ts from nginx log
NGINX_TMP=$(mktemp)
if [[ -n "$nginx_log" ]]; then
  echo "$nginx_log" | awk '
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
    # Use mktime (GNU awk) to convert to epoch
    epoch = mktime(dt[3]" "mo" "dt[1]" "dt[4]" "dt[5]" "dt[6])
    print ip"\t"epoch
  }' > "$NGINX_TMP"
fi

# For each blocked IP in window, check if it had nginx hits before blocked_at
preemptive=0
reactive=0
nginx_requests_before_block=0

if [[ -n "$total_blocked" && "$total_blocked" -gt 0 ]]; then
  while IFS='|' read -r ip blocked_at; do
    # Count nginx requests from this IP before blocked_at
    req_before=$(awk -v ip="$ip" -v bt="$blocked_at" -v since="$SINCE_EPOCH" \
      'BEGIN{c=0} $1==ip && $2>=since && $2<bt {c++} END{print c}' "$NGINX_TMP")
    if [[ "$req_before" -eq 0 ]]; then
      ((preemptive++)) || true
    else
      ((reactive++)) || true
      ((nginx_requests_before_block+=req_before)) || true
    fi
  done < <(q "SELECT ip, blocked_at FROM blocks WHERE blocked_at >= $SINCE_EPOCH;")
fi
rm -f "$NGINX_TMP"

echo "── Coverage ──────────────────────────────────────────────────────────────────"
printf "IPs blocked in window:               %d\n" "$total_blocked"
if [[ "$total_blocked" -gt 0 ]]; then
  printf "  preemptive (no prior nginx hit):   %d  (%d%%)\n" \
    "$preemptive" "$((preemptive*100/total_blocked))"
  printf "  reactive (nginx hit before block): %d  (%d%%)\n" \
    "$reactive" "$((reactive*100/total_blocked))"
fi
printf "Nginx requests served before block:  %d\n" "$nginx_requests_before_block"
echo ""

# ── Time-to-Block Latency ─────────────────────────────────────────────────────
latencies=$(q "
  SELECT b.blocked_at - MIN(e.ts)
  FROM blocks b
  JOIN events e ON e.ip = b.ip AND e.ts <= b.blocked_at
  WHERE b.blocked_at >= $SINCE_EPOCH
  GROUP BY b.ip, b.blocked_at
  ORDER BY 1;
")

if [[ -n "$latencies" ]]; then
  read -r median p95 fastest <<< "$(echo "$latencies" | awk '
  {a[NR]=$1}
  END{
    n=NR
    med=a[int(n/2)+1]
    p95=a[int(n*0.95)+1]
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
  printf "Median: %s    P95: %s    Fastest: %s\n" \
    "$(fmt_sec $median)" "$(fmt_sec $p95)" "$(fmt_sec $fastest)"
else
  echo "── Time-to-Block Latency ─────────────────────────────────────────────────────"
  echo "No blocks in window."
fi
echo ""

# ── False Positive Risk ───────────────────────────────────────────────────────
single_source=$(q "
  SELECT COUNT(DISTINCT b.ip)
  FROM blocks b
  WHERE b.blocked_at >= $SINCE_EPOCH
    AND (SELECT COUNT(DISTINCT reporter) FROM events e
         WHERE e.ip=b.ip AND e.ts<=b.blocked_at) = 1;
")

auto_unblocked=$(q "
  SELECT COUNT(*) FROM blocks
  WHERE blocked_at >= $SINCE_EPOCH AND unblocked_at IS NOT NULL;
")

returned=$(q "
  SELECT COUNT(*) FROM blocks b
  WHERE b.blocked_at >= $SINCE_EPOCH
    AND b.unblocked_at IS NOT NULL
    AND EXISTS (
      SELECT 1 FROM blocks b2
      WHERE b2.ip=b.ip AND b2.blocked_at > b.unblocked_at
    );
")

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
cs_window="${WINDOW_LABEL}"
# cscli --since accepts formats like "24h", "7d" — approximate from window
cs_since_hours=$(( (NOW - SINCE_EPOCH) / 3600 ))
cs_json=$(docker exec "$CROWDSEC_CTR" \
  cscli decisions list -o json --since "${cs_since_hours}h" 2>/dev/null) || cs_json="[]"

cs_ips=$(echo "$cs_json" | jq -r '.[].value // empty' 2>/dev/null | sort -u) || cs_ips=""
swarm_ips=$(q "SELECT DISTINCT ip FROM blocks WHERE blocked_at >= $SINCE_EPOCH AND unblocked_at IS NULL;" | sort)

cs_count=$(echo "$cs_ips" | grep -c . || true)
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
  printf "  SwarmGuard-only (federation):      %d\n" "$swarm_only"
fi

# Top scenarios
echo ""
echo "Top CrowdSec scenarios:"
echo "$cs_json" | jq -r '.[].scenario // empty' 2>/dev/null | sort | uniq -c | sort -rn | head -5 \
  | awk '{printf "  %-42s %d\n", $2, $1}' || true

# Top countries
echo ""
echo "Top countries:"
echo "$cs_json" | jq -r '.[].country // empty' 2>/dev/null | sort | uniq -c | sort -rn | head -5 \
  | awk '{printf "  %s: %d  ", $2, $1}' && echo "" || true
echo ""

# ── Rule Breakdown ────────────────────────────────────────────────────────────
echo "── Rule Breakdown ────────────────────────────────────────────────────────────"
printf "%-32s %6s  %12s  %10s  %8s\n" "Rule" "Fires" "Slip-through" "Single-src" "Returned"

q "
  SELECT rf.rule, COUNT(DISTINCT b.ip)
  FROM blocks b
  JOIN (SELECT ip, rule, MIN(ts) AS fire_ts FROM rule_firings WHERE action='block' GROUP BY ip) rf
    ON rf.ip = b.ip
  WHERE b.blocked_at >= $SINCE_EPOCH
  GROUP BY rf.rule
  ORDER BY COUNT(DISTINCT b.ip) DESC;
" | while IFS='|' read -r rule fires; do
  # Single-source for this rule
  ss=$(q "
    SELECT COUNT(DISTINCT b.ip)
    FROM blocks b
    JOIN (SELECT ip, rule, MIN(ts) AS fire_ts FROM rule_firings WHERE action='block' GROUP BY ip) rf
      ON rf.ip = b.ip AND rf.rule='$rule'
    WHERE b.blocked_at >= $SINCE_EPOCH
      AND (SELECT COUNT(DISTINCT reporter) FROM events e
           WHERE e.ip=b.ip AND e.ts<=b.blocked_at) = 1;
  ")
  # Returned for this rule
  ret=$(q "
    SELECT COUNT(*) FROM blocks b
    JOIN (SELECT ip, rule FROM rule_firings WHERE action='block' GROUP BY ip) rf
      ON rf.ip=b.ip AND rf.rule='$rule'
    WHERE b.blocked_at >= $SINCE_EPOCH
      AND b.unblocked_at IS NOT NULL
      AND EXISTS(SELECT 1 FROM blocks b2 WHERE b2.ip=b.ip AND b2.blocked_at>b.unblocked_at);
  ")
  printf "%-32s %6d  %12s  %10s  %8s\n" "$rule" "$fires" "—" "$ss" "$ret"
done
echo ""

# ── Active Blocklist ──────────────────────────────────────────────────────────
current=$(q "SELECT COUNT(*) FROM blocks WHERE unblocked_at IS NULL;")
oldest=$(q "SELECT MIN(datetime(blocked_at,'unixepoch')) FROM blocks WHERE unblocked_at IS NULL;")
echo "── Active Blocklist ──────────────────────────────────────────────────────────"
printf "Currently blocked:  %s IPs\n" "$current"
printf "Oldest active block: %s\n" "$oldest"
```

- [ ] **Step 2: Make executable, commit, and deploy**

```bash
chmod +x deploy/wordpress/effectiveness-report.sh
git add deploy/wordpress/effectiveness-report.sh
git commit -m "feat(wordpress): add on-demand effectiveness report script

Covers coverage (preemptive vs reactive blocks), time-to-block latency,
false-positive risk indicators, CrowdSec cross-reference, and per-rule
breakdown — all configurable with --hours/--days/--since.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

Deploy to wordpress:
```bash
rsync -az deploy/wordpress/effectiveness-report.sh \
  root@d.jru.me:/opt/swarmguard/deploy/wordpress/
```

- [ ] **Step 3: Run the report on wordpress and verify output**

```bash
ssh -p 2222 root@d.jru.me \
  "/opt/swarmguard/deploy/wordpress/effectiveness-report.sh --hours 24"
```

Expected: full report printed with all sections populated. The rule breakdown table should show at least `crowdsec-decision` or `score-fallback` rows. Verify no bash errors (`set -euo pipefail` will abort on any error).

---

## Verification Checklist

After all tasks complete, verify end-to-end:

```bash
# 1. Go metrics appear in SwarmGuard /metrics on wordpress
curl -s http://d.jru.me:9101/metrics | grep "swarmguard_blocks_total\|swarmguard_time_to_block\|swarmguard_corroboration\|swarmguard_unblocks_total\|swarmguard_block_recurrence"

# 2. Textfile exporter metrics appear in node_exporter
ssh -p 2222 root@d.jru.me "curl -s http://localhost:9100/metrics | grep swarmguard_"

# 3. CLI report runs without errors
ssh -p 2222 root@d.jru.me "/opt/swarmguard/deploy/wordpress/effectiveness-report.sh --days 7"

# 4. All existing tests still pass
cd /root/swarmguard && make test
```
