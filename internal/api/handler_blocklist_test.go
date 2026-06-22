package api

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/store"
)

// listStoreStub implements StoreReader with three fixed IPs for blocklist tests:
//
//	10.0.0.1 — smtp-auth-bruteforce (mail, score 90)
//	10.0.0.2 — http-scan            (web,  score 80)
//	10.0.0.3 — ssh-auth-bruteforce  (ssh,  score 70)
type listStoreStub struct{}

func (s *listStoreStub) GetScore(ip string) (store.ScoreRecord, error) {
	// Not used by blocklist handlers.
	return store.ScoreRecord{}, nil
}

func (s *listStoreStub) ScanScores(fn func(ip string, r store.ScoreRecord) error) error {
	now := time.Now()
	fixtures := []struct {
		ip  string
		rec store.ScoreRecord
	}{
		{
			ip: "10.0.0.1",
			rec: store.ScoreRecord{
				Score:    90.0,
				LastSeen: now,
				Reasons:  []string{"smtp-auth-bruteforce"},
			},
		},
		{
			ip: "10.0.0.2",
			rec: store.ScoreRecord{
				Score:    80.0,
				LastSeen: now,
				Reasons:  []string{"http-scan"},
			},
		},
		{
			ip: "10.0.0.3",
			rec: store.ScoreRecord{
				Score:    70.0,
				LastSeen: now,
				Reasons:  []string{"ssh-auth-bruteforce"},
			},
		},
	}
	for _, f := range fixtures {
		if err := fn(f.ip, f.rec); err != nil {
			return err
		}
	}
	return nil
}

func newListServer() *Server {
	return New(
		config.APIConfig{Addr: ":0"},
		&listStoreStub{},
		config.ReputationConfig{BlockThreshold: 75},
	)
}

func TestHandleBlocklist_All(t *testing.T) {
	srv := newListServer()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/blocklist", nil)
	w := httptest.NewRecorder()

	srv.handleBlocklist(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var entries []blockEntry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// threshold=75 → 10.0.0.1 (90) and 10.0.0.2 (80) pass; 10.0.0.3 (70) does not.
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	// Sorted descending: first entry should be 10.0.0.1 (score 90).
	if entries[0].Score != 90.0 {
		t.Errorf("entries[0].Score = %v, want 90.0", entries[0].Score)
	}
	if entries[1].Score != 80.0 {
		t.Errorf("entries[1].Score = %v, want 80.0", entries[1].Score)
	}
}

func TestHandleBlocklist_Purpose(t *testing.T) {
	srv := newListServer()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/blocklist?purpose=mail&min_score=0", nil)
	w := httptest.NewRecorder()

	srv.handleBlocklist(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}

	var entries []blockEntry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Only smtp-* matches the "mail" purpose; min_score=0 so score doesn't filter.
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].IP != "10.0.0.1" {
		t.Errorf("IP = %q, want 10.0.0.1", entries[0].IP)
	}
	if !containsReason(entries[0].Reasons, "smtp-auth-bruteforce") {
		t.Errorf("reasons %v do not contain smtp-auth-bruteforce", entries[0].Reasons)
	}
}

func TestHandleBlocklist_ReasonFilter(t *testing.T) {
	srv := newListServer()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/blocklist?reason=smtp-*&min_score=0", nil)
	w := httptest.NewRecorder()

	srv.handleBlocklist(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}

	var entries []blockEntry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].IP != "10.0.0.1" {
		t.Errorf("IP = %q, want 10.0.0.1", entries[0].IP)
	}
}

func TestHandleCrowdSecCTI_PlainText(t *testing.T) {
	srv := newListServer()

	r := httptest.NewRequest(http.MethodGet, "/crowdsec/v1/decisions?min_score=0", nil)
	w := httptest.NewRecorder()

	srv.handleCrowdSecCTI(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}

	// All 3 IPs at min_score=0.
	body := w.Body.String()
	lines := countNonEmptyLines(body)
	if lines != 3 {
		t.Errorf("got %d lines, want 3\nbody:\n%s", lines, body)
	}

	// Each line should be a plain IP address (no score/reasons).
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "{") || strings.Contains(line, ":") {
			t.Errorf("line %q looks like JSON or key:value — expected plain IP", line)
		}
	}
}

// containsReason is a test helper.
func containsReason(reasons []string, target string) bool {
	for _, r := range reasons {
		if r == target {
			return true
		}
	}
	return false
}

// countNonEmptyLines counts non-empty lines in s.
func countNonEmptyLines(s string) int {
	n := 0
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		if scanner.Text() != "" {
			n++
		}
	}
	return n
}

// malformedKeyStore returns one valid IP and one CIDR key to test sanitization.
type malformedKeyStore struct{}

func (s *malformedKeyStore) GetScore(ip string) (store.ScoreRecord, error) {
	return store.ScoreRecord{}, nil
}

func (s *malformedKeyStore) ScanScores(fn func(ip string, r store.ScoreRecord) error) error {
	now := time.Now()
	_ = fn("203.0.113.1", store.ScoreRecord{Score: 90.0, LastSeen: now, Reasons: []string{"ssh-probe"}})
	_ = fn("0.0.0.0/0", store.ScoreRecord{Score: 90.0, LastSeen: now, Reasons: []string{"ssh-probe"}})
	return nil
}

// TestHandleCrowdSecCTI_SkipsMalformedKeys verifies that malformed store keys
// (CIDRs, newline-embedded strings) are not emitted in the CTI plaintext feed.
func TestHandleCrowdSecCTI_SkipsMalformedKeys(t *testing.T) {
	srv := New(
		config.APIConfig{Addr: ":0"},
		&malformedKeyStore{},
		config.ReputationConfig{BlockThreshold: 0},
	)
	r := httptest.NewRequest(http.MethodGet, "/crowdsec/v1/decisions?min_score=0", nil)
	w := httptest.NewRecorder()

	srv.handleCrowdSecCTI(w, r)

	body := w.Body.String()
	lines := countNonEmptyLines(body)
	if lines != 1 {
		t.Errorf("got %d lines, want 1 (malformed key must be skipped)\nbody: %q", lines, body)
	}
	if !strings.Contains(body, "203.0.113.1") {
		t.Errorf("valid IP missing from CTI output; body: %q", body)
	}
	if strings.Contains(body, "0.0.0.0/0") {
		t.Errorf("CIDR key leaked into CTI output; body: %q", body)
	}
}
