package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/store"
)

// stubStore implements StoreReader with no-op methods for testing.
type stubStore struct{}

func (s *stubStore) GetScore(ip string) (store.ScoreRecord, error) {
	return store.ScoreRecord{}, nil
}

func (s *stubStore) ScanScores(fn func(ip string, r store.ScoreRecord) error) error {
	return nil
}

// TestNew verifies that New with a disabled (empty) addr returns a non-nil
// Server and that the taxonomy is resolved to at least the default entries.
func TestNew(t *testing.T) {
	cfg := config.APIConfig{Addr: "", Purpose: "", Taxonomy: nil}
	srv := New(cfg, &stubStore{}, config.ReputationConfig{})
	if srv == nil {
		t.Fatal("New returned nil")
	}
	if srv.subs == nil {
		t.Error("subs map is nil")
	}
	// Taxonomy must contain at least the default keys.
	for _, key := range []string{"mail", "web", "ssh"} {
		if _, ok := srv.taxonomy[key]; !ok {
			t.Errorf("resolved taxonomy missing key %q", key)
		}
	}
}

// TestBroadcastDisabled checks that Broadcast on a server with an empty addr
// does not panic (no-op path).
func TestBroadcastDisabled(t *testing.T) {
	srv := New(config.APIConfig{Addr: ""}, &stubStore{}, config.ReputationConfig{})
	// Must not panic.
	srv.Broadcast("1.2.3.4", 50.0, "ssh-auth", "peer-1")
}

// TestBroadcastToSubscriber verifies that a subscribed channel receives the
// broadcast message within a short timeout.
func TestBroadcastToSubscriber(t *testing.T) {
	srv := New(config.APIConfig{Addr: ":0"}, &stubStore{}, config.ReputationConfig{})

	ch := srv.subscribe()
	defer srv.unsubscribe(ch)

	srv.Broadcast("10.0.0.1", 80.0, "smtp-auth", "peer-2")

	select {
	case msg := <-ch:
		if msg.IP != "10.0.0.1" {
			t.Errorf("got IP %q, want 10.0.0.1", msg.IP)
		}
		if msg.Score != 80.0 {
			t.Errorf("got score %v, want 80.0", msg.Score)
		}
		if msg.Reason != "smtp-auth" {
			t.Errorf("got reason %q, want smtp-auth", msg.Reason)
		}
		if msg.Reporter != "peer-2" {
			t.Errorf("got reporter %q, want peer-2", msg.Reporter)
		}
		if msg.TS.IsZero() {
			t.Error("TS is zero")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for broadcast message")
	}
}

// TestUnsubscribeClosesChan verifies that after unsubscribe the channel is
// closed (receiving from a closed channel returns immediately with zero value).
func TestUnsubscribeClosesChan(t *testing.T) {
	srv := New(config.APIConfig{Addr: ":0"}, &stubStore{}, config.ReputationConfig{})

	ch := srv.subscribe()
	srv.unsubscribe(ch)

	// A closed channel is immediately readable and returns the zero value.
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("channel should be closed but received a value")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out — channel was not closed")
	}
}

// TestBearerTokenMiddleware_MissingHeader verifies that a request without
// an Authorization header is rejected with 401.
func TestBearerTokenMiddleware_MissingHeader(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := bearerTokenMiddleware("secret", next)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}

// TestBearerTokenMiddleware_WrongToken verifies that a request with an
// incorrect bearer token is rejected with 401.
func TestBearerTokenMiddleware_WrongToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := bearerTokenMiddleware("secret", next)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}

// TestBearerTokenMiddleware_CorrectToken verifies that a request with the
// correct bearer token is allowed through to the next handler.
func TestBearerTokenMiddleware_CorrectToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := bearerTokenMiddleware("secret", next)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("got %d, want 200", w.Code)
	}
}

// TestBearerTokenMiddleware_EmptyAuthHeader verifies that a request with an
// empty Authorization header is rejected with 401.
func TestBearerTokenMiddleware_EmptyAuthHeader(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := bearerTokenMiddleware("secret", next)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}
