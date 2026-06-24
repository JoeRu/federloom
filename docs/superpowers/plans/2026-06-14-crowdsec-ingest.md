# CrowdSec Ingest Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the `internal/ingest/crowdsec.go` stub as a fully working `ingest.Source` that polls a local CrowdSec LAPI for decisions and alerts, translating them into `proto.Event`s that flow through FederLoom's trust, scoring, and rules pipeline.

**Architecture:** Single adapter (`CrowdSec`) with one polling goroutine; fetches `/v1/decisions/stream` then `/v1/alerts` per tick. New `CrowdSecConfig` in `IngestConfig`. Node wires the source when `enabled: true`. Three new rules in `rules.yaml` cover the two emitted reason strings.

**Tech Stack:** Go 1.22, `net/http`, `encoding/json`, `net/url` (all stdlib). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-06-14-crowdsec-ingest-design.md`

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `internal/config/config.go` | `CrowdSecConfig` struct, `IngestConfig.CrowdSec`, `Defaults()` |
| Modify | `internal/ingest/crowdsec.go` | Full adapter — replaces 6-line stub |
| Create | `internal/ingest/crowdsec_test.go` | 7 httptest-based unit tests |
| Modify | `internal/node/node.go` | Wire CrowdSec source after OpenCanary block |
| Modify | `deploy/examples/rules.yaml` | 3 new CrowdSec rules before `score-fallback` |
| Modify | `deploy/examples/config.solo.yaml` | Commented `crowdsec:` example block |
| Modify | `CHANGELOG.md` | Feature entry |

---

## Task 1: Config — CrowdSecConfig

**Files:**
- Modify: `internal/config/config.go`

- [ ] **Step 1: Add `CrowdSecConfig` struct and update `IngestConfig`**

In `internal/config/config.go`, replace the `IngestConfig` struct (currently ends at `OpenCanary OpenCanaryConfig`) with:

```go
// IngestConfig groups all ingest source configs.
type IngestConfig struct {
	Honeypot   HoneypotConfig   `yaml:"honeypot"`
	OpenCanary OpenCanaryConfig `yaml:"opencanary"`
	CrowdSec   CrowdSecConfig   `yaml:"crowdsec"`
}

// CrowdSecConfig configures the CrowdSec LAPI ingest adapter.
type CrowdSecConfig struct {
	Enabled         bool     `yaml:"enabled"`
	LAPIURL         string   `yaml:"lapi_url"`
	APIKey          string   `yaml:"api_key"`
	PollInterval    Duration `yaml:"poll_interval"`
	EnableDecisions bool     `yaml:"enable_decisions"`
	EnableAlerts    bool     `yaml:"enable_alerts"`
}
```

- [ ] **Step 2: Update `Defaults()` to set CrowdSec poll interval and enable both stream types**

In `Defaults()`, update the `Ingest` field initializer:

```go
Ingest: IngestConfig{
    Honeypot: HoneypotConfig{
        PollInterval: Duration{time.Second},
    },
    OpenCanary: OpenCanaryConfig{
        PollInterval: Duration{time.Second},
    },
    CrowdSec: CrowdSecConfig{
        PollInterval:    Duration{30 * time.Second},
        EnableDecisions: true,
        EnableAlerts:    true,
        // Enabled: false (zero value — opt-in)
    },
},
```

- [ ] **Step 3: Verify config compiles**

```bash
go build ./internal/config/...
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add CrowdSecConfig to IngestConfig"
```

---

## Task 2: Tests — crowdsec_test.go

Write the tests before the implementation so compilation failure confirms what's missing.

**Files:**
- Create: `internal/ingest/crowdsec_test.go`

- [ ] **Step 1: Create the test file**

```go
package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/pkg/proto"
)

// crowdSecForTest returns a CrowdSec adapter pointed at the given test-server URL.
func crowdSecForTest(t *testing.T, url string) *CrowdSec {
	t.Helper()
	return NewCrowdSec(config.CrowdSecConfig{
		LAPIURL:         url,
		APIKey:          "test-key",
		EnableDecisions: true,
		EnableAlerts:    true,
	}, "self-test")
}

func TestCrowdSec_Name(t *testing.T) {
	cs := NewCrowdSec(config.CrowdSecConfig{}, "")
	if got := cs.Name(); got != "crowdsec" {
		t.Errorf("Name() = %q, want %q", got, "crowdsec")
	}
}

func TestCrowdSec_FetchDecisions_Startup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(csDecisionStream{
			New: []csDecision{
				{Value: "1.2.3.4", Type: "ban", Scenario: "crowdsecurity/ssh-bf"},
				{Value: "5.6.7.8", Type: "ban", Scenario: "crowdsecurity/http-probing"},
			},
		})
	}))
	defer srv.Close()

	cs := crowdSecForTest(t, srv.URL)
	ch := make(chan proto.Event, 10)
	cs.fetchDecisions(context.Background(), ch)

	if len(ch) != 2 {
		t.Fatalf("got %d events, want 2", len(ch))
	}
	for range 2 {
		e := <-ch
		if e.Reason != "crowdsec-decision" {
			t.Errorf("Reason = %q, want crowdsec-decision", e.Reason)
		}
		if e.ReporterID != "self-test" {
			t.Errorf("ReporterID = %q, want self-test", e.ReporterID)
		}
	}
}

func TestCrowdSec_FetchDecisions_SkipsNonBan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(csDecisionStream{
			New: []csDecision{
				{Value: "1.2.3.4", Type: "captcha", Scenario: "crowdsecurity/ssh-bf"},
			},
		})
	}))
	defer srv.Close()

	cs := crowdSecForTest(t, srv.URL)
	ch := make(chan proto.Event, 10)
	cs.fetchDecisions(context.Background(), ch)
	if len(ch) != 0 {
		t.Errorf("got %d events, want 0 (captcha type must be skipped)", len(ch))
	}
}

func TestCrowdSec_FetchDecisions_SkipsDeleted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(csDecisionStream{
			Deleted: []csDecision{
				{Value: "1.2.3.4", Type: "ban"},
			},
		})
	}))
	defer srv.Close()

	cs := crowdSecForTest(t, srv.URL)
	ch := make(chan proto.Event, 10)
	cs.fetchDecisions(context.Background(), ch)
	if len(ch) != 0 {
		t.Errorf("got %d events from deleted array, want 0", len(ch))
	}
}

func TestCrowdSec_FetchAlerts_ScenarioMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]csAlert{
			{Source: csAlertSource{IP: "1.2.3.4"}, Scenario: "crowdsecurity/ssh-bf", StartAt: time.Now().UTC().Format(time.RFC3339)},
			{Source: csAlertSource{IP: "5.6.7.8"}, Scenario: "crowdsecurity/novelty", StartAt: time.Now().UTC().Format(time.RFC3339)},
		})
	}))
	defer srv.Close()

	cs := crowdSecForTest(t, srv.URL)
	ch := make(chan proto.Event, 10)
	cs.fetchAlerts(context.Background(), ch)
	if len(ch) != 2 {
		t.Fatalf("got %d events, want 2", len(ch))
	}
	e1 := <-ch
	e2 := <-ch
	if e1.Reason != "ssh-auth-bruteforce" {
		t.Errorf("known scenario reason = %q, want ssh-auth-bruteforce", e1.Reason)
	}
	if e2.Reason != "crowdsec-alert" {
		t.Errorf("unknown scenario reason = %q, want crowdsec-alert", e2.Reason)
	}
}

func TestCrowdSec_FetchAlerts_Since(t *testing.T) {
	callCount := 0
	var sinceParam string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 2 {
			sinceParam = r.URL.Query().Get("since")
		}
		json.NewEncoder(w).Encode([]csAlert{})
	}))
	defer srv.Close()

	cs := crowdSecForTest(t, srv.URL)
	ch := make(chan proto.Event, 10)
	before := time.Now()
	cs.fetchAlerts(context.Background(), ch) // first poll — sets lastAlert ≈ before
	cs.fetchAlerts(context.Background(), ch) // second poll — must send ?since=lastAlert

	if sinceParam == "" {
		t.Fatal("second poll did not include ?since= parameter")
	}
	since, err := time.Parse(time.RFC3339, sinceParam)
	if err != nil {
		t.Fatalf("since is not valid RFC3339: %q: %v", sinceParam, err)
	}
	// since must fall in the window of the first poll
	if since.Before(before.Add(-time.Second)) {
		t.Errorf("since %v is more than 1s before first poll start %v", since, before)
	}
}

func TestCrowdSec_LAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cs := crowdSecForTest(t, srv.URL)
	ch := make(chan proto.Event, 10)
	cs.fetchDecisions(context.Background(), ch)
	cs.fetchAlerts(context.Background(), ch)
	if len(ch) != 0 {
		t.Errorf("got %d events on LAPI error, want 0", len(ch))
	}
}
```

- [ ] **Step 2: Run tests — expect compilation failure**

```bash
go test ./internal/ingest/... 2>&1 | head -30
```

Expected: `undefined: CrowdSec` / `undefined: csDecisionStream` (confirms stub needs full implementation).

---

## Task 3: Adapter — crowdsec.go

**Files:**
- Modify: `internal/ingest/crowdsec.go`

- [ ] **Step 1: Replace the stub with the full implementation**

Replace the entire content of `internal/ingest/crowdsec.go`:

```go
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/pkg/proto"
)

// scenarioMap translates known CrowdSec scenario names to FederLoom reason strings.
// Unknown scenarios fall back to "crowdsec-alert".
var scenarioMap = map[string]string{
	"crowdsecurity/ssh-bf":           "ssh-auth-bruteforce",
	"crowdsecurity/ssh-slow-bf":      "ssh-auth-bruteforce",
	"crowdsecurity/ssh-bf-wordpress": "ssh-auth-bruteforce",
	"crowdsecurity/http-probing":     "http-probe",
	"crowdsecurity/http-bf":          "http-probe",
	"crowdsecurity/smtp-bf":          "smtp-auth-bruteforce",
}

// CrowdSec polls a local CrowdSec LAPI instance for decisions and alerts.
type CrowdSec struct {
	cfg       config.CrowdSecConfig
	selfID    string
	client    *http.Client
	startup   bool      // drives ?startup= param on /decisions/stream
	lastAlert time.Time // upper bound for next /alerts?since= query
}

// Compile-time check: CrowdSec must implement Source.
var _ Source = (*CrowdSec)(nil)

// NewCrowdSec creates a CrowdSec ingest source.
func NewCrowdSec(cfg config.CrowdSecConfig, selfID string) *CrowdSec {
	return &CrowdSec{
		cfg:     cfg,
		selfID:  selfID,
		client:  &http.Client{Timeout: 10 * time.Second},
		startup: true,
	}
}

func (c *CrowdSec) Name() string { return "crowdsec" }

// Start launches the polling goroutine and returns the event channel.
func (c *CrowdSec) Start(ctx context.Context) (<-chan proto.Event, error) {
	if c.cfg.LAPIURL == "" {
		return nil, fmt.Errorf("crowdsec: lapi_url is required")
	}
	if c.cfg.APIKey == "" {
		return nil, fmt.Errorf("crowdsec: api_key is required")
	}
	interval := c.cfg.PollInterval.Duration
	if interval <= 0 {
		interval = 30 * time.Second
	}

	ch := make(chan proto.Event, 64)
	go func() {
		defer close(ch)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if c.cfg.EnableDecisions {
					c.fetchDecisions(ctx, ch)
				}
				if c.cfg.EnableAlerts {
					c.fetchAlerts(ctx, ch)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

// --- decisions ---

type csDecision struct {
	Value    string `json:"value"`
	Type     string `json:"type"`
	Scenario string `json:"scenario"`
	Origin   string `json:"origin"`
}

type csDecisionStream struct {
	New     []csDecision `json:"new"`
	Deleted []csDecision `json:"deleted"`
}

func (c *CrowdSec) fetchDecisions(ctx context.Context, ch chan<- proto.Event) {
	startup := "false"
	if c.startup {
		startup = "true"
	}
	u := c.cfg.LAPIURL + "/v1/decisions/stream?startup=" + startup

	resp, err := c.get(ctx, u)
	if err != nil {
		log.Printf("crowdsec: decisions fetch: %v", err)
		return
	}
	defer resp.Body.Close()

	var stream csDecisionStream
	if err := json.NewDecoder(resp.Body).Decode(&stream); err != nil {
		log.Printf("crowdsec: decisions decode: %v", err)
		return
	}
	c.startup = false // flip after first successful fetch

	now := time.Now()
	for _, d := range stream.New {
		if d.Type != "ban" || d.Value == "" {
			continue
		}
		select {
		case ch <- proto.Event{
			IP:         d.Value,
			Reason:     "crowdsec-decision",
			Timestamp:  now,
			ReporterID: c.selfID,
		}:
		case <-ctx.Done():
			return
		}
	}
	// Deleted decisions are ignored: FederLoom releases IPs via score decay.
}

// --- alerts ---

type csAlertSource struct {
	IP string `json:"ip"`
}

type csAlert struct {
	Source   csAlertSource `json:"source"`
	Scenario string        `json:"scenario"`
	StartAt  string        `json:"startAt"` // RFC3339
}

func (c *CrowdSec) fetchAlerts(ctx context.Context, ch chan<- proto.Event) {
	since := c.lastAlert
	if since.IsZero() {
		since = time.Now().Add(-24 * time.Hour) // bootstrap: last 24h on first poll
	}

	u := c.cfg.LAPIURL + "/v1/alerts?since=" + url.QueryEscape(since.UTC().Format(time.RFC3339)) + "&limit=500"
	resp, err := c.get(ctx, u)
	if err != nil {
		log.Printf("crowdsec: alerts fetch: %v", err)
		return
	}
	defer resp.Body.Close()

	var alerts []csAlert
	if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
		log.Printf("crowdsec: alerts decode: %v", err)
		return
	}

	pollTime := time.Now()
	for _, a := range alerts {
		if a.Source.IP == "" {
			continue
		}
		reason := mapScenario(a.Scenario)
		ts, err := time.Parse(time.RFC3339, a.StartAt)
		if err != nil {
			ts = pollTime
		}
		select {
		case ch <- proto.Event{
			IP:         a.Source.IP,
			Reason:     reason,
			Timestamp:  ts,
			ReporterID: c.selfID,
		}:
		case <-ctx.Done():
			return
		}
	}
	c.lastAlert = pollTime
}

func mapScenario(scenario string) string {
	if r, ok := scenarioMap[scenario]; ok {
		return r
	}
	return "crowdsec-alert"
}

// get performs an authenticated GET against the LAPI.
func (c *CrowdSec) get(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("LAPI returned %d for %s", resp.StatusCode, rawURL)
	}
	return resp, nil
}
```

- [ ] **Step 2: Run tests — expect all 7 to pass**

```bash
go test ./internal/ingest/... -v -run TestCrowdSec
```

Expected:
```
--- PASS: TestCrowdSec_Name (0.00s)
--- PASS: TestCrowdSec_FetchDecisions_Startup (0.00s)
--- PASS: TestCrowdSec_FetchDecisions_SkipsNonBan (0.00s)
--- PASS: TestCrowdSec_FetchDecisions_SkipsDeleted (0.00s)
--- PASS: TestCrowdSec_FetchAlerts_ScenarioMapping (0.00s)
--- PASS: TestCrowdSec_FetchAlerts_Since (0.00s)
--- PASS: TestCrowdSec_LAPIError (0.00s)
PASS
```

- [ ] **Step 3: Run full test suite — no regressions**

```bash
go test ./...
```

Expected: all existing tests still pass.

- [ ] **Step 4: Commit**

```bash
git add internal/ingest/crowdsec.go internal/ingest/crowdsec_test.go
git commit -m "feat(ingest): implement CrowdSec LAPI adapter"
```

---

## Task 4: Integration — Node, Rules, Example Config, CHANGELOG

**Files:**
- Modify: `internal/node/node.go`
- Modify: `deploy/examples/rules.yaml`
- Modify: `deploy/examples/config.solo.yaml`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Wire CrowdSec source in `internal/node/node.go`**

Find the OpenCanary block (currently around line 90–92):

```go
if cfg.Ingest.OpenCanary.Enabled {
    sources = append(sources, ingest.NewOpenCanary(cfg.Ingest.OpenCanary, selfID))
}
```

Add immediately after it:

```go
if cfg.Ingest.CrowdSec.Enabled {
    sources = append(sources, ingest.NewCrowdSec(cfg.Ingest.CrowdSec, selfID))
}
```

- [ ] **Step 2: Add 3 CrowdSec rules to `deploy/examples/rules.yaml`**

Insert before the `score-fallback` rule (currently the last rule):

```yaml
# CrowdSec decision — confirmed ban from local CrowdSec instance.
- name: crowdsec-decision
  reason: crowdsec-decision
  min_corroboration: 1
  action: block

# CrowdSec alert corroborated by a second source (honeypot or peer).
- name: crowdsec-alert-corroborated
  reason: crowdsec-alert
  min_corroboration: 2
  action: block

# Unknown CrowdSec scenario seen by at least one source — watch only.
- name: crowdsec-alert-watch
  reason: crowdsec-alert
  min_corroboration: 1
  action: watch

```

- [ ] **Step 3: Add commented crowdsec block to `deploy/examples/config.solo.yaml`**

Append to the file:

```yaml
ingest:
  crowdsec:
    enabled: false          # set to true after: cscli bouncers add federloom
    lapi_url: "http://localhost:8080"
    api_key: ""             # paste bouncer key here — never commit; use config.local.yaml
    poll_interval: 30s
    enable_decisions: true
    enable_alerts: true
```

- [ ] **Step 4: Add CHANGELOG entry**

Under the `## [Unreleased]` section (or create it if absent), add:

```markdown
### Added
- **CrowdSec ingest adapter** (`internal/ingest/crowdsec.go`): polls `/v1/decisions/stream`
  and `/v1/alerts` from a local CrowdSec LAPI instance; decisions emit
  `crowdsec-decision` events, alerts map via `scenarioMap` to existing FederLoom
  reason strings or fall back to `crowdsec-alert`. Opt-in via `ingest.crowdsec.enabled`.
- Three CrowdSec rules in `deploy/examples/rules.yaml`: `crowdsec-decision` (block),
  `crowdsec-alert-corroborated` (block ≥ 2 sources), `crowdsec-alert-watch` (watch).
```

- [ ] **Step 5: Build and run full test suite**

```bash
go build ./... && go test ./...
```

Expected: clean build, all tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/node/node.go deploy/examples/rules.yaml deploy/examples/config.solo.yaml CHANGELOG.md
git commit -m "feat(ingest): wire CrowdSec source; add rules and example config"
```

---

## Self-Review

**Spec coverage:**

| Spec requirement | Task |
|---|---|
| `CrowdSecConfig` with all 6 fields | Task 1 |
| `Defaults()` sets 30s poll, both streams enabled | Task 1 |
| `/v1/decisions/stream?startup=` cursor | Task 3 (adapter) |
| `/v1/alerts?since=&limit=500` | Task 3 (adapter) |
| `scenarioMap` + `crowdsec-alert` fallback | Task 3 (adapter) |
| `startup` flag flips after first success | Task 3 + Test |
| `lastAlert` updated after each alerts poll | Task 3 + Test |
| Non-ban decisions skipped | Task 2 (test) + Task 3 |
| Deleted decisions ignored | Task 2 (test) + Task 3 |
| Non-200 LAPI response = log + skip | Task 2 (test) + Task 3 |
| `var _ Source = (*CrowdSec)(nil)` compile guard | Task 3 |
| Node wiring behind `Enabled` flag | Task 4 |
| 3 CrowdSec rules in rules.yaml | Task 4 |
| `api_key` never committed note | Task 4 (config.solo.yaml comment) |
| CHANGELOG | Task 4 |

**Backwards compatibility:** `Enabled: false` zero value — existing deployments unchanged.

**No placeholder violations:** all steps contain actual code.
