# CrowdSec Ingest Adapter Design

**Goal:** Implement the `internal/ingest/crowdsec.go` stub as a fully working ingest source that polls a local CrowdSec LAPI instance for both decisions and alerts, translating them into `proto.Event`s that flow through SwarmGuard's trust, scoring, and rules pipeline.

**Architecture:** Single adapter (`ingest.Source`) with one polling goroutine that fetches `/v1/decisions/stream` and `/v1/alerts` sequentially per tick. Decisions emit high-confidence `crowdsec-decision` events; alerts map CrowdSec scenarios to SwarmGuard reason strings. HTTP errors skip the tick and retry on the next interval.

**Tech Stack:** Go 1.22, `net/http` (stdlib), `encoding/json`, `gopkg.in/yaml.v3` (existing).

**Spec:** This is sub-project 1 of 2 for the "smoke test + observability" initiative. Sub-project 2 (score reporting + live monitoring via `swarmctl score`) follows separately.

---

## Context: What already exists

- `internal/ingest/plugin.go` — `Source` interface: `Name() string`, `Start(ctx) (<-chan proto.Event, error)`
- `internal/ingest/honeypot.go` + `opencanary.go` — reference implementations to follow
- `internal/ingest/crowdsec.go` — stub (2-line comment only)
- `internal/config/config.go` — `IngestConfig` with `Honeypot` and `OpenCanary` fields; add `CrowdSec CrowdSecConfig`
- `internal/node/node.go` — wires sources in `New()`:
  ```go
  if cfg.Ingest.Honeypot.Enabled { sources = append(sources, ingest.NewHoneypot(...)) }
  if cfg.Ingest.OpenCanary.Enabled { sources = append(sources, ingest.NewOpenCanary(...)) }
  ```
- `deploy/examples/rules.yaml` — add CrowdSec rules after existing entries
- `pkg/proto/messages.go` — `proto.Event{IP, Reason, Timestamp, ReporterID, ...}`

---

## Config

### New `CrowdSecConfig` struct (internal/config/config.go)

Add to `IngestConfig`:

```go
type IngestConfig struct {
    Honeypot   HoneypotConfig   `yaml:"honeypot"`
    OpenCanary OpenCanaryConfig `yaml:"opencanary"`
    CrowdSec   CrowdSecConfig   `yaml:"crowdsec"`   // NEW
}

// CrowdSecConfig configures the CrowdSec LAPI ingest adapter.
type CrowdSecConfig struct {
    Enabled         bool     `yaml:"enabled"`
    LAPIURL         string   `yaml:"lapi_url"`         // e.g. http://localhost:8080
    APIKey          string   `yaml:"api_key"`           // bouncer key: cscli bouncers add swarmguard
    PollInterval    Duration `yaml:"poll_interval"`     // default 30s
    EnableDecisions bool     `yaml:"enable_decisions"`  // pull /v1/decisions/stream
    EnableAlerts    bool     `yaml:"enable_alerts"`     // pull /v1/alerts
}
```

`Defaults()` additions:
```go
CrowdSec: CrowdSecConfig{
    PollInterval:    Duration{30 * time.Second},
    EnableDecisions: true,
    EnableAlerts:    true,
    // Enabled: false (zero value = opt-in)
},
```

### Example config block (deploy/examples/config.solo.yaml)

```yaml
ingest:
  crowdsec:
    enabled: false          # set to true after: cscli bouncers add swarmguard
    lapi_url: "http://localhost:8080"
    api_key: ""             # paste bouncer key here (never commit)
    poll_interval: 30s
    enable_decisions: true
    enable_alerts: true
```

`api_key` must never be committed. `.gitignore` already excludes `config.local.yaml`; operators keep secrets there.

---

## Adapter Implementation

### File: internal/ingest/crowdsec.go

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

    "github.com/JoeRu/swarmguard/internal/config"
    "github.com/JoeRu/swarmguard/pkg/proto"
)

// scenarioMap translates known CrowdSec scenario names to SwarmGuard reason strings.
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
    Value    string `json:"value"`    // IP address
    Type     string `json:"type"`     // "ban"
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
    // Deleted decisions are ignored: SwarmGuard releases IPs via score decay.
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

---

## Node Wiring (internal/node/node.go)

Add after the OpenCanary block in `New()`:

```go
if cfg.Ingest.CrowdSec.Enabled {
    sources = append(sources, ingest.NewCrowdSec(cfg.Ingest.CrowdSec, selfID))
}
```

---

## Example Rules (deploy/examples/rules.yaml)

Add before the `score-fallback` rule:

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

---

## Tests

### internal/ingest/crowdsec_test.go

Use `httptest.NewServer` to mock the LAPI — no real CrowdSec instance needed.

- `TestCrowdSec_Name` — `Name()` returns `"crowdsec"`
- `TestCrowdSec_FetchDecisions_Startup` — mock `/v1/decisions/stream?startup=true` returns 2 new bans; verify 2 events emitted with `reason="crowdsec-decision"`
- `TestCrowdSec_FetchDecisions_SkipsNonBan` — decision with `type="captcha"` not emitted
- `TestCrowdSec_FetchDecisions_SkipsDeleted` — `deleted` array not emitted
- `TestCrowdSec_FetchAlerts_ScenarioMapping` — known scenario maps to correct reason; unknown maps to `"crowdsec-alert"`
- `TestCrowdSec_FetchAlerts_Since` — second poll sends `?since=` param after first poll
- `TestCrowdSec_LAPIError` — non-200 response logs warning, no panic, no events

---

## Backwards Compatibility

`Enabled: false` by default. Existing deployments are unaffected. No existing tests touch the CrowdSec adapter. The `config.go` `Defaults()` change is additive.

---

## Files Created / Modified

| Action | Path |
|--------|------|
| Modify | `internal/ingest/crowdsec.go` — full implementation (replaces stub) |
| Create | `internal/ingest/crowdsec_test.go` |
| Modify | `internal/config/config.go` — add `CrowdSecConfig`, update `IngestConfig`, update `Defaults()` |
| Modify | `internal/node/node.go` — wire CrowdSec source |
| Modify | `deploy/examples/rules.yaml` — add 3 CrowdSec rules |
| Modify | `deploy/examples/config.solo.yaml` — add commented crowdsec block |
| Modify | `CHANGELOG.md` |
