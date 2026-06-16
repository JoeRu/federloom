package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestScoreIP_Found(t *testing.T) {
	want := ScoreResponse{
		IP:            "1.2.3.4",
		Score:         0.85,
		Corroboration: 3,
		FirstSeen:     "2024-01-01T00:00:00Z",
		LastSeen:      "2024-06-01T12:00:00Z",
		Reasons:       []string{"spam", "brute-force"},
		Blocked:       true,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/1.2.3.4") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := New(srv.URL)
	got, err := c.ScoreIP(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("ScoreIP returned error: %v", err)
	}
	if got.IP != want.IP {
		t.Errorf("IP: got %q, want %q", got.IP, want.IP)
	}
	if got.Score != want.Score {
		t.Errorf("Score: got %f, want %f", got.Score, want.Score)
	}
	if got.Corroboration != want.Corroboration {
		t.Errorf("Corroboration: got %d, want %d", got.Corroboration, want.Corroboration)
	}
	if got.Blocked != want.Blocked {
		t.Errorf("Blocked: got %v, want %v", got.Blocked, want.Blocked)
	}
	if len(got.Reasons) != len(want.Reasons) {
		t.Errorf("Reasons length: got %d, want %d", len(got.Reasons), len(want.Reasons))
	}
}

func TestScoreIP_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer srv.Close()

	c := New(srv.URL)
	got, err := c.ScoreIP(context.Background(), "9.9.9.9")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if got != nil {
		t.Errorf("expected nil response, got %+v", got)
	}
	if !strings.Contains(err.Error(), "9.9.9.9") {
		t.Errorf("error message should contain IP, got: %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error message should contain 'not found', got: %v", err)
	}
}

func TestBlocklist(t *testing.T) {
	ts := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	want := []BlockEntry{
		{IP: "1.2.3.4", Score: 0.9, LastSeen: ts, Reasons: []string{"spam"}},
		{IP: "5.6.7.8", Score: 0.75, LastSeen: ts, Reasons: []string{"brute-force"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/blocklist" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := New(srv.URL)
	got, err := c.Blocklist(context.Background(), BlocklistOpts{})
	if err != nil {
		t.Fatalf("Blocklist returned error: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d entries, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i].IP != want[i].IP {
			t.Errorf("entry %d IP: got %q, want %q", i, got[i].IP, want[i].IP)
		}
		if got[i].Score != want[i].Score {
			t.Errorf("entry %d Score: got %f, want %f", i, got[i].Score, want[i].Score)
		}
	}
}

func TestBlocklist_WithOpts(t *testing.T) {
	var capturedQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]BlockEntry{})
	}))
	defer srv.Close()

	c := New(srv.URL)
	opts := BlocklistOpts{
		MinScore: 0.7,
		Purpose:  "mail",
		Reasons:  []string{"spam", "phishing"},
	}
	_, err := c.Blocklist(context.Background(), opts)
	if err != nil {
		t.Fatalf("Blocklist returned error: %v", err)
	}

	if got := capturedQuery.Get("min_score"); got != "0.7" {
		t.Errorf("min_score: got %q, want %q", got, "0.7")
	}
	if got := capturedQuery.Get("purpose"); got != "mail" {
		t.Errorf("purpose: got %q, want %q", got, "mail")
	}
	if got := capturedQuery.Get("reason"); got != "spam,phishing" {
		t.Errorf("reason: got %q, want %q", got, "spam,phishing")
	}
}

func TestBlocklist_WithOpts_NoFilters(t *testing.T) {
	var capturedQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]BlockEntry{})
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Blocklist(context.Background(), BlocklistOpts{})
	if err != nil {
		t.Fatalf("Blocklist returned error: %v", err)
	}

	// When opts are zero values, no query params should be set.
	if got := capturedQuery.Get("min_score"); got != "" {
		t.Errorf("expected no min_score param, got %q", got)
	}
	if got := capturedQuery.Get("purpose"); got != "" {
		t.Errorf("expected no purpose param, got %q", got)
	}
	if got := capturedQuery.Get("reason"); got != "" {
		t.Errorf("expected no reason param, got %q", got)
	}
}

func TestEvents(t *testing.T) {
	ts := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	events := []EventMsg{
		{IP: "1.2.3.4", Score: 0.9, Reason: "spam", Reporter: "peer1", TS: ts},
		{IP: "5.6.7.8", Score: 0.6, Reason: "brute-force", Reporter: "peer2", TS: ts},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("responsewriter does not implement Flusher")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")

		// Send the initial keepalive.
		fmt.Fprintf(w, "data: connected\n\n")
		flusher.Flush()

		// Send two events.
		for _, ev := range events {
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}

		// Hold the connection until the client context is cancelled.
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())

	c := New(srv.URL)
	ch, err := c.Events(ctx)
	if err != nil {
		t.Fatalf("Events returned error: %v", err)
	}

	// Collect the two expected events.
	received := make([]EventMsg, 0, 2)
	for i := 0; i < 2; i++ {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed before receiving all events (got %d)", i)
			}
			received = append(received, msg)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for event %d", i)
		}
	}

	// Cancel and wait for the channel to close.
	cancel()
	select {
	case <-ch:
		// closed — good
	case <-time.After(5 * time.Second):
		t.Fatal("channel not closed after ctx cancel")
	}

	// Verify event content.
	for i, want := range events {
		got := received[i]
		if got.IP != want.IP {
			t.Errorf("event %d IP: got %q, want %q", i, got.IP, want.IP)
		}
		if got.Reason != want.Reason {
			t.Errorf("event %d Reason: got %q, want %q", i, got.Reason, want.Reason)
		}
		if got.Reporter != want.Reporter {
			t.Errorf("event %d Reporter: got %q, want %q", i, got.Reporter, want.Reporter)
		}
		if got.Score != want.Score {
			t.Errorf("event %d Score: got %f, want %f", i, got.Score, want.Score)
		}
	}
}
