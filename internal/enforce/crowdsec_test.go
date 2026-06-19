package enforce_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/enforce"
)

// mockLAPI sets up a fake CrowdSec LAPI server and returns a CrowdSecSink
// configured to talk to it. Each handler function can be nil to use a sensible
// default (200 OK with a valid JWT for login, 200 OK for everything else).
func mockLAPI(t *testing.T,
	loginHandler func(w http.ResponseWriter, r *http.Request),
	alertsHandler func(w http.ResponseWriter, r *http.Request),
	decisionsHandler func(w http.ResponseWriter, r *http.Request),
) (*httptest.Server, *enforce.CrowdSecSink) {
	t.Helper()

	defaultJWT := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":  "test-jwt-token",
			"expire": expiry,
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		if loginHandler != nil {
			loginHandler(w, r)
		} else {
			defaultJWT(w, r)
		}
	})
	mux.HandleFunc("/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		if alertsHandler != nil {
			alertsHandler(w, r)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})
	mux.HandleFunc("/v1/decisions", func(w http.ResponseWriter, r *http.Request) {
		if decisionsHandler != nil {
			decisionsHandler(w, r)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := config.EnforceConfig{
		CrowdSecLAPIURL:         srv.URL,
		CrowdSecMachineID:       "testmachine",
		CrowdSecMachinePassword: "testpass",
	}
	sink := enforce.NewCrowdSec(cfg, 7*24*time.Hour)
	return srv, sink
}

func TestCrowdSecSink_Block(t *testing.T) {
	var loginCalls, alertCalls int

	_, sink := mockLAPI(t,
		func(w http.ResponseWriter, r *http.Request) {
			loginCalls++
			if r.Method != http.MethodPost {
				t.Errorf("login: expected POST, got %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token":  "test-jwt-token",
				"expire": expiry,
			})
		},
		func(w http.ResponseWriter, r *http.Request) {
			alertCalls++
			if r.Method != http.MethodPost {
				t.Errorf("alerts: expected POST, got %s", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("alerts: expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
			}
			if r.Header.Get("Authorization") == "" {
				t.Error("alerts: expected Authorization header to be set")
			}

			// Verify the body contains the expected fields.
			var payload []map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("alerts: decode body: %v", err)
			}
			if len(payload) != 1 {
				t.Fatalf("alerts: expected 1 alert, got %d", len(payload))
			}
			alert := payload[0]
			decisions, ok := alert["decisions"].([]interface{})
			if !ok || len(decisions) != 1 {
				t.Fatalf("alerts: expected 1 decision, got %v", alert["decisions"])
			}
			decision := decisions[0].(map[string]interface{})
			if decision["ip"] != "1.2.3.4" {
				t.Errorf("alerts: expected ip=1.2.3.4, got %v", decision["ip"])
			}
			if decision["origin"] != "swarmguard" {
				t.Errorf("alerts: expected origin=swarmguard, got %v", decision["origin"])
			}
			if decision["type"] != "ban" {
				t.Errorf("alerts: expected type=ban, got %v", decision["type"])
			}
			w.WriteHeader(http.StatusOK)
		},
		nil,
	)

	ctx := context.Background()
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if loginCalls != 1 {
		t.Errorf("expected 1 login call during Start, got %d", loginCalls)
	}

	if err := sink.Block("1.2.3.4"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if alertCalls != 1 {
		t.Errorf("expected 1 alerts call, got %d", alertCalls)
	}
}

func TestCrowdSecSink_Unblock(t *testing.T) {
	var decisionsCalls int

	_, sink := mockLAPI(t,
		nil,
		nil,
		func(w http.ResponseWriter, r *http.Request) {
			decisionsCalls++
			if r.Method != http.MethodDelete {
				t.Errorf("decisions: expected DELETE, got %s", r.Method)
			}
			if r.Header.Get("Authorization") == "" {
				t.Error("decisions: expected Authorization header to be set")
			}
			q := r.URL.Query()
			if q.Get("origin") != "swarmguard" {
				t.Errorf("decisions: expected origin=swarmguard, got %q", q.Get("origin"))
			}
			if q.Get("value") != "5.6.7.8" {
				t.Errorf("decisions: expected value=5.6.7.8, got %q", q.Get("value"))
			}
			w.WriteHeader(http.StatusOK)
		},
	)

	if err := sink.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := sink.Unblock("5.6.7.8"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if decisionsCalls != 1 {
		t.Errorf("expected 1 decisions DELETE call, got %d", decisionsCalls)
	}
}

func TestCrowdSecSink_StartFail(t *testing.T) {
	// LAPI returns 401 on the auth endpoint.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := config.EnforceConfig{
		CrowdSecLAPIURL:         srv.URL,
		CrowdSecMachineID:       "badmachine",
		CrowdSecMachinePassword: "testpass",
	}
	sink := enforce.NewCrowdSec(cfg, 0)

	err := sink.Start(context.Background())
	if err == nil {
		t.Fatal("expected Start to return error when LAPI returns 401, got nil")
	}
}
