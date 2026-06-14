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
