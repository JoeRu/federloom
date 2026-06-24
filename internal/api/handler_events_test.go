package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
)

// noFlushWriter is an http.ResponseWriter that explicitly does NOT implement
// http.Flusher, used to test the 501 path. httptest.ResponseRecorder does
// implement Flusher in current Go versions, so we need our own type.
type noFlushWriter struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func newNoFlushWriter() *noFlushWriter {
	return &noFlushWriter{header: make(http.Header), code: http.StatusOK}
}

func (w *noFlushWriter) Header() http.Header         { return w.header }
func (w *noFlushWriter) WriteHeader(code int)        { w.code = code }
func (w *noFlushWriter) Write(b []byte) (int, error) { return w.body.Write(b) }

// flushRecorder wraps httptest.ResponseRecorder and tracks flush calls.
type flushRecorder struct {
	*httptest.ResponseRecorder
	mu      sync.Mutex
	flushed int
}

func newFlushRecorder() *flushRecorder {
	return &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func (f *flushRecorder) Flush() {
	f.mu.Lock()
	f.flushed++
	f.mu.Unlock()
	f.ResponseRecorder.Flush()
}

func (f *flushRecorder) FlushCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushed
}

// newTestServer creates a Server with a non-empty Addr so Broadcast is active.
func newTestServer() *Server {
	return New(
		config.APIConfig{Addr: "127.0.0.1:0"},
		nil, // store not needed for SSE tests
		config.ReputationConfig{},
	)
}

// TestHandleEvents_NoFlusher verifies that a non-flusher ResponseWriter
// causes the handler to return 501 Streaming Not Supported.
func TestHandleEvents_NoFlusher(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	w := newNoFlushWriter() // explicitly does NOT implement http.Flusher

	srv.handleEvents(w, req)

	if w.code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", w.code)
	}
	if !strings.Contains(w.body.String(), "streaming not supported") {
		t.Errorf("expected body to contain 'streaming not supported', got: %q", w.body.String())
	}
}

// TestHandleEvents_Connect verifies the full happy path:
// - handler sends "data: connected" immediately
// - handler forwards a broadcast event as JSON
// - context cancellation causes a clean exit
func TestHandleEvents_Connect(t *testing.T) {
	srv := newTestServer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
	rec := newFlushRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleEvents(rec, req)
	}()

	// Give the handler time to reach the subscribe/flush point.
	time.Sleep(5 * time.Millisecond)

	// Broadcast one event.
	srv.Broadcast("10.0.0.1", 0.9, "ssh-brute", "peer1")

	// Give the handler time to write the event.
	time.Sleep(5 * time.Millisecond)

	// Cancel the context so the handler exits.
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not exit after context cancellation")
	}

	body := rec.Body.String()
	if !strings.Contains(body, "data: connected") {
		t.Errorf("expected body to contain 'data: connected', got: %q", body)
	}
	if !strings.Contains(body, `"ip":"10.0.0.1"`) {
		t.Errorf("expected body to contain broadcast IP, got: %q", body)
	}
}

// TestHandleEvents_Disconnect verifies that cancelling the request context
// causes the handler to return without blocking.
func TestHandleEvents_Disconnect(t *testing.T) {
	srv := newTestServer()

	ctx, cancel := context.WithCancel(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
	rec := newFlushRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleEvents(rec, req)
	}()

	// Wait for the handler to be in the select loop.
	time.Sleep(5 * time.Millisecond)

	// Cancel — handler should exit.
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not exit after context cancellation")
	}

	body := rec.Body.String()
	if !strings.Contains(body, "data: connected") {
		t.Errorf("expected initial keepalive, got: %q", body)
	}
}
