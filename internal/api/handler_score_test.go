package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/store"
)

// scoreStoreStub implements StoreReader with fixed data for score handler tests.
type scoreStoreStub struct{}

func (s *scoreStoreStub) GetScore(ip string) (store.ScoreRecord, error) {
	switch ip {
	case "1.2.3.4":
		return store.ScoreRecord{
			Score:         90.0,
			Corroboration: 3,
			FirstSeen:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			LastSeen:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			Reasons:       []string{"ssh-auth-bruteforce"},
		}, nil
	default:
		// Not found: zero ScoreRecord, LastSeen.IsZero() == true.
		return store.ScoreRecord{}, nil
	}
}

func (s *scoreStoreStub) ScanScores(fn func(ip string, r store.ScoreRecord) error) error {
	return nil
}

func newScoreServer() *Server {
	return New(
		config.APIConfig{Addr: ":0"},
		&scoreStoreStub{},
		config.ReputationConfig{BlockThreshold: 75},
	)
}

func TestHandleScore_Found(t *testing.T) {
	srv := newScoreServer()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/score/1.2.3.4", nil)
	r.SetPathValue("ip", "1.2.3.4")
	w := httptest.NewRecorder()

	srv.handleScore(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp["ip"] != "1.2.3.4" {
		t.Errorf("ip = %v, want 1.2.3.4", resp["ip"])
	}
	if resp["score"] != 90.0 {
		t.Errorf("score = %v, want 90.0", resp["score"])
	}
	// blocked should be true since 90.0 >= 75.0
	if resp["blocked"] != true {
		t.Errorf("blocked = %v, want true", resp["blocked"])
	}
	if _, ok := resp["first_seen"]; !ok {
		t.Error("first_seen missing from response")
	}
	if _, ok := resp["last_seen"]; !ok {
		t.Error("last_seen missing from response")
	}
}

func TestHandleScore_NotFound(t *testing.T) {
	srv := newScoreServer()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/score/9.9.9.9", nil)
	r.SetPathValue("ip", "9.9.9.9")
	w := httptest.NewRecorder()

	srv.handleScore(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("got status %d, want 404", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["error"] != "not found" {
		t.Errorf("error = %q, want \"not found\"", resp["error"])
	}
}

func TestHandleScore_MissingIP(t *testing.T) {
	srv := newScoreServer()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/score/", nil)
	// No SetPathValue call → PathValue("ip") returns "" → 400
	w := httptest.NewRecorder()

	srv.handleScore(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["error"] != "missing IP" {
		t.Errorf("error = %q, want \"missing IP\"", resp["error"])
	}
}
