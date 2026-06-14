package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// crowdSecForTest returns a CrowdSec adapter in bouncer-only mode (decisions, no alerts).
func crowdSecForTest(t *testing.T, url string) *CrowdSec {
	t.Helper()
	return NewCrowdSec(config.CrowdSecConfig{
		LAPIURL:         url,
		APIKey:          "test-key",
		EnableDecisions: true,
		EnableAlerts:    false,
	}, "self-test")
}

// crowdSecMachineForTest returns a CrowdSec adapter in machine-only mode (alerts, no decisions).
func crowdSecMachineForTest(t *testing.T, url string) *CrowdSec {
	t.Helper()
	return NewCrowdSec(config.CrowdSecConfig{
		LAPIURL:         url,
		MachineID:       "agent1",
		MachinePassword: "secret",
		EnableDecisions: false,
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
		if r.URL.Path == "/v1/watchers/login" {
			json.NewEncoder(w).Encode(csAuthResp{Token: "tok", Expire: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			return
		}
		json.NewEncoder(w).Encode([]csAlert{
			{Source: csAlertSource{IP: "1.2.3.4"}, Scenario: "crowdsecurity/ssh-bf", StartAt: time.Now().UTC().Format(time.RFC3339)},
			{Source: csAlertSource{IP: "5.6.7.8"}, Scenario: "crowdsecurity/novelty", StartAt: time.Now().UTC().Format(time.RFC3339)},
		})
	}))
	defer srv.Close()

	cs := crowdSecMachineForTest(t, srv.URL)
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
	var mu sync.Mutex
	callCount := 0
	var sinceParam string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/watchers/login" {
			json.NewEncoder(w).Encode(csAuthResp{Token: "tok", Expire: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			return
		}
		mu.Lock()
		callCount++
		if callCount == 2 {
			sinceParam = r.URL.Query().Get("since")
		}
		mu.Unlock()
		json.NewEncoder(w).Encode([]csAlert{})
	}))
	defer srv.Close()

	cs := crowdSecMachineForTest(t, srv.URL)
	ch := make(chan proto.Event, 10)
	before := time.Now()
	cs.fetchAlerts(context.Background(), ch) // first poll — sets lastAlert ≈ before
	cs.fetchAlerts(context.Background(), ch) // second poll — must send ?since=lastAlert

	mu.Lock()
	sp := sinceParam
	mu.Unlock()

	if sp == "" {
		t.Fatal("second poll did not include ?since= parameter")
	}
	since, err := time.Parse(time.RFC3339, sp)
	if err != nil {
		t.Fatalf("since is not valid RFC3339: %q: %v", sp, err)
	}
	if since.Before(before.Add(-time.Second)) {
		t.Errorf("since %v is more than 1s before first poll start %v", since, before)
	}
}

func TestCrowdSec_LAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Decisions error (bouncer mode).
	cs := crowdSecForTest(t, srv.URL)
	ch := make(chan proto.Event, 10)
	cs.fetchDecisions(context.Background(), ch)
	if len(ch) != 0 {
		t.Errorf("got %d events on LAPI error, want 0", len(ch))
	}

	// Alerts error (machine mode — seed JWT to bypass auth call).
	csm := crowdSecMachineForTest(t, srv.URL)
	csm.jwtMu.Lock()
	csm.jwt = "tok"
	csm.jwtExpiry = time.Now().Add(time.Hour)
	csm.jwtMu.Unlock()
	csm.fetchAlerts(context.Background(), ch)
	if len(ch) != 0 {
		t.Errorf("got %d events on alerts LAPI error, want 0", len(ch))
	}
}

func TestCrowdSec_MachineAuth(t *testing.T) {
	const fakeJWT = "eyJ.test.token"
	var mu sync.Mutex
	authCalls := 0
	var lastAuthHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/watchers/login":
			var req csAuthReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if req.MachineID != "agent1" || req.Password != "secret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			mu.Lock()
			authCalls++
			mu.Unlock()
			json.NewEncoder(w).Encode(csAuthResp{
				Token:  fakeJWT,
				Expire: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			})
		case "/v1/alerts":
			mu.Lock()
			lastAuthHeader = r.Header.Get("Authorization")
			mu.Unlock()
			json.NewEncoder(w).Encode([]csAlert{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cs := crowdSecMachineForTest(t, srv.URL)

	// Authenticate and then fetchAlerts — which uses machine JWT via getWithMachine.
	if err := cs.authenticate(context.Background()); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	ch := make(chan proto.Event, 10)
	cs.fetchAlerts(context.Background(), ch)

	mu.Lock()
	auth := lastAuthHeader
	calls := authCalls
	mu.Unlock()

	if !strings.HasPrefix(auth, "Bearer ") {
		t.Errorf("Authorization header = %q, want Bearer token", auth)
	}
	if !strings.Contains(auth, fakeJWT) {
		t.Errorf("Authorization header = %q, want JWT %q", auth, fakeJWT)
	}
	if calls != 1 {
		t.Errorf("auth called %d times, want 1", calls)
	}
}
