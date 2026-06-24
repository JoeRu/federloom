// Package enforce is the data plane: the only place that writes to the firewall.
// CrowdSec blocklist sink — pushes FederLoom's federated reputation decisions
// to a local CrowdSec LAPI instance so an existing cs-firewall-bouncer enforces
// them (drop-in, spec §3).
package enforce

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/JoeRu/federloom/internal/config"
)

// CrowdSecSink pushes block decisions to a CrowdSec LAPI as machine-account
// alerts. The LAPI then distributes them to any registered bouncer (e.g.
// cs-firewall-bouncer), keeping FederLoom non-invasive (spec §3).
type CrowdSecSink struct {
	cfg       config.EnforceConfig
	halfLife  time.Duration
	client    *http.Client
	jwtMu     sync.Mutex
	jwt       string
	jwtExpiry time.Time
	banDur    time.Duration
}

// Compile-time interface check.
var _ Sink = (*CrowdSecSink)(nil)

// NewCrowdSec creates a CrowdSecSink. halfLife is used as the ban duration when
// cfg.CrowdSecBanDuration is zero; if both are zero, 168 h (7 days) is used.
func NewCrowdSec(cfg config.EnforceConfig, halfLife time.Duration) *CrowdSecSink {
	banDur := cfg.CrowdSecBanDuration.Duration
	if banDur <= 0 {
		if halfLife > 0 {
			banDur = halfLife
		} else {
			banDur = 168 * time.Hour
		}
	}
	return &CrowdSecSink{
		cfg:      cfg,
		halfLife: halfLife,
		client:   &http.Client{Timeout: 10 * time.Second},
		banDur:   banDur,
	}
}

func (s *CrowdSecSink) Name() string { return "crowdsec" }

// Start authenticates with the LAPI. Returns an error if the LAPI is
// unreachable or rejects the credentials.
func (s *CrowdSecSink) Start(ctx context.Context) error {
	if s.cfg.CrowdSecLAPIURL == "" {
		return fmt.Errorf("enforce/crowdsec: crowdsec_lapi_url is required")
	}
	if s.cfg.CrowdSecMachineID == "" || s.cfg.CrowdSecMachinePassword == "" {
		return fmt.Errorf("enforce/crowdsec: crowdsec_machine_id and crowdsec_machine_password are required")
	}
	authCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.authenticate(authCtx)
}

// Block pushes a ban alert for ip to the CrowdSec LAPI (/v1/alerts).
func (s *CrowdSecSink) Block(ip string) error {
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)

	type csDecision struct {
		Duration string `json:"duration"`
		IP       string `json:"ip"`
		Origin   string `json:"origin"`
		Scenario string `json:"scenario"`
		Scope    string `json:"scope"`
		Type     string `json:"type"`
		Value    string `json:"value"`
	}
	type csSource struct {
		IP    string `json:"ip"`
		Scope string `json:"scope"`
		Value string `json:"value"`
	}
	type csAlert struct {
		Capacity        int          `json:"capacity"`
		Decisions       []csDecision `json:"decisions"`
		Events          []struct{}   `json:"events"`
		EventsCount     int          `json:"events_count"`
		LeakSpeed       string       `json:"leakspeed"`
		Message         string       `json:"message"`
		Scenario        string       `json:"scenario"`
		ScenarioHash    string       `json:"scenario_hash"`
		ScenarioVersion string       `json:"scenario_version"`
		Simulated       bool         `json:"simulated"`
		Source          csSource     `json:"source"`
		StartAt         string       `json:"start_at"`
		StopAt          string       `json:"stop_at"`
	}

	alert := csAlert{
		Capacity: 0,
		Decisions: []csDecision{{
			Duration: s.banDur.String(),
			IP:       ip,
			Origin:   "federloom",
			Scenario: "federloom/reputation",
			Scope:    "Ip",
			Type:     "ban",
			Value:    ip,
		}},
		Events:          []struct{}{},
		EventsCount:     1,
		LeakSpeed:       "",
		Message:         "federloom reputation block",
		Scenario:        "federloom/reputation",
		ScenarioHash:    "",
		ScenarioVersion: "",
		Simulated:       false,
		Source: csSource{
			IP:    ip,
			Scope: "Ip",
			Value: ip,
		},
		StartAt: now,
		StopAt:  now,
	}

	body, err := json.Marshal([]csAlert{alert})
	if err != nil {
		return fmt.Errorf("enforce/crowdsec: marshal alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.CrowdSecLAPIURL+"/v1/alerts", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("enforce/crowdsec: create block request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if err := s.authRequest(ctx, req); err != nil {
		return fmt.Errorf("enforce/crowdsec: block auth: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("enforce/crowdsec: block request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("enforce/crowdsec: block %s returned %d", ip, resp.StatusCode)
	}
	return nil
}

// Unblock deletes all federloom-origin decisions for ip from the LAPI.
// CrowdSec v1.5+ supports filter-delete via ?origin=&value= query parameters.
func (s *CrowdSecSink) Unblock(ip string) error {
	ctx := context.Background()

	u := s.cfg.CrowdSecLAPIURL + "/v1/decisions?origin=federloom&value=" + url.QueryEscape(ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return fmt.Errorf("enforce/crowdsec: create unblock request: %w", err)
	}

	if err := s.authRequest(ctx, req); err != nil {
		return fmt.Errorf("enforce/crowdsec: unblock auth: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("enforce/crowdsec: unblock request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("enforce/crowdsec: unblock %s returned %d", ip, resp.StatusCode)
	}
	return nil
}

// Close is a no-op: the LAPI retains decisions across restarts.
func (s *CrowdSecSink) Close() error { return nil }

// --- internal auth helpers ---

type csEnforcedAuthReq struct {
	MachineID string   `json:"machine_id"`
	Password  string   `json:"password"`
	Scenarios []string `json:"scenarios"`
}

type csEnforcedAuthResp struct {
	Token  string `json:"token"`
	Expire string `json:"expire"` // RFC3339
}

// authenticate POSTs to /v1/watchers/login and stores the JWT under jwtMu.
func (s *CrowdSecSink) authenticate(ctx context.Context) error {
	body, err := json.Marshal(csEnforcedAuthReq{
		MachineID: s.cfg.CrowdSecMachineID,
		Password:  s.cfg.CrowdSecMachinePassword,
		Scenarios: []string{},
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.CrowdSecLAPIURL+"/v1/watchers/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enforce/crowdsec: auth returned %d", resp.StatusCode)
	}

	var ar csEnforcedAuthResp
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return err
	}
	expiry, err := time.Parse(time.RFC3339, ar.Expire)
	if err != nil {
		expiry = time.Now().Add(23 * time.Hour)
	}

	s.jwtMu.Lock()
	s.jwt = ar.Token
	s.jwtExpiry = expiry
	s.jwtMu.Unlock()
	return nil
}

// authRequest refreshes the JWT if it is within 5 minutes of expiry, then sets
// the Authorization header on req.
func (s *CrowdSecSink) authRequest(ctx context.Context, req *http.Request) error {
	s.jwtMu.Lock()
	needsRefresh := s.jwt == "" || time.Now().After(s.jwtExpiry.Add(-5*time.Minute))
	s.jwtMu.Unlock()

	if needsRefresh {
		if err := s.authenticate(ctx); err != nil {
			return fmt.Errorf("enforce/crowdsec: re-authenticate: %w", err)
		}
	}

	s.jwtMu.Lock()
	jwt := s.jwt
	s.jwtMu.Unlock()

	req.Header.Set("Authorization", "Bearer "+jwt)
	return nil
}
