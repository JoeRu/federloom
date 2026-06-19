package api

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/store"
)

// StoreReader is the read-only subset of store.BadgerStore used by the API.
// Defined as an interface to avoid import cycles when wiring up from main.
type StoreReader interface {
	GetScore(ip string) (store.ScoreRecord, error)
	ScanScores(fn func(ip string, r store.ScoreRecord) error) error
}

// EventMsg is the payload sent to SSE subscribers on every scored event.
type EventMsg struct {
	IP       string    `json:"ip"`
	Score    float64   `json:"score"`
	Reason   string    `json:"reason"`
	Reporter string    `json:"reporter"`
	TS       time.Time `json:"ts"`
}

// Server is the optional local HTTP API (spec §3).
// A zero-addr Server is inert: all methods are safe to call but do nothing.
type Server struct {
	cfg      config.APIConfig
	store    StoreReader
	repCfg   config.ReputationConfig
	taxonomy config.TaxonomyConfig // resolved via ResolveTaxonomy
	mu       sync.RWMutex
	subs     map[chan EventMsg]struct{}
}

// New creates a Server.  The taxonomy from cfg is merged with DefaultTaxonomy
// via ResolveTaxonomy so callers can pass a partial or nil taxonomy.
func New(cfg config.APIConfig, s StoreReader, repCfg config.ReputationConfig) *Server {
	return &Server{
		cfg:      cfg,
		store:    s,
		repCfg:   repCfg,
		taxonomy: ResolveTaxonomy(cfg.Taxonomy),
		subs:     make(map[chan EventMsg]struct{}),
	}
}

// Start binds the HTTP server and registers all API routes.
// It is a no-op when s is nil or cfg.Addr is empty (server disabled).
// The server shuts down gracefully when ctx is cancelled.
func (s *Server) Start(ctx context.Context) {
	if s == nil || s.cfg.Addr == "" {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/score/{ip}", s.handleScore)
	mux.HandleFunc("GET /api/v1/blocklist", s.handleBlocklist)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	mux.HandleFunc("GET /crowdsec/v1/decisions", s.handleCrowdSecCTI)

	srv := &http.Server{Addr: s.cfg.Addr, Handler: mux}

	go func() {
		log.Printf("api: listening on %s", s.cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("api: server error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
}

// Broadcast sends an event to all active SSE subscribers.
// It is a no-op when s is nil or the server is disabled (empty addr).
// Slow subscribers are dropped non-blocking.
func (s *Server) Broadcast(ip string, score float64, reason, reporter string) {
	if s == nil || s.cfg.Addr == "" {
		return
	}
	msg := EventMsg{
		IP:       ip,
		Score:    score,
		Reason:   reason,
		Reporter: reporter,
		TS:       time.Now(),
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

// subscribe allocates a buffered channel, registers it for broadcasts, and
// returns it.  The caller must call unsubscribe when done.
func (s *Server) subscribe() chan EventMsg {
	ch := make(chan EventMsg, 64)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

// unsubscribe removes ch from the subscriber set and closes it.
func (s *Server) unsubscribe(ch chan EventMsg) {
	s.mu.Lock()
	delete(s.subs, ch)
	s.mu.Unlock()
	close(ch)
}
