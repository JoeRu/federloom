package reputation

import (
	"fmt"
	"time"

	"github.com/JoeRu/swarmguard/internal/store"
)

// reportWeight maps event reason to score contribution weight.
var reportWeight = map[string]float64{
	"ssh-auth-success":      40,
	"ssh-auth-bruteforce":   10,
	"ssh-post-auth-command": 10,
	"ssh-probe":             2,
	"ssh-unknown":           2,
}

func weightFor(reason string) float64 {
	if w, ok := reportWeight[reason]; ok {
		return w
	}
	return 2
}

// Engine computes IP reputation scores using lazy decay and logistic accumulation.
type Engine struct {
	store    *store.BadgerStore
	halfLife time.Duration
}

// New creates an Engine backed by s with the given half-life for decay.
func New(s *store.BadgerStore, halfLife time.Duration) *Engine {
	return &Engine{store: s, halfLife: halfLife}
}

// Record applies one observation to ip's score and returns the new score.
// trust is 1.0 for local ground-truth sources, 0.3 for remote peers.
func (e *Engine) Record(ip, reason, reporterID string, trust float64) (float64, error) {
	rec, err := e.store.GetScore(ip)
	if err != nil {
		return 0, fmt.Errorf("reputation: get %q: %w", ip, err)
	}

	now := time.Now()

	// Lazy decay: apply time-based decay since last observation.
	if !rec.LastSeen.IsZero() {
		rec.Score = DecayScore(rec.Score, rec.LastSeen, now, e.halfLife)
	}

	// Logistic accumulation: score approaches 100 asymptotically.
	weight := weightFor(reason)
	rec.Score += trust * weight * (1 - rec.Score/100)
	if rec.Score > 100 {
		rec.Score = 100
	}

	// Corroboration: count distinct reporters.
	if !containsString(rec.ReporterIDs, reporterID) {
		rec.ReporterIDs = append(rec.ReporterIDs, reporterID)
		rec.Corroboration = len(rec.ReporterIDs)
	}

	// Update metadata.
	rec.LastSeen = now
	if rec.FirstSeen.IsZero() {
		rec.FirstSeen = now
	}
	if !containsString(rec.Reasons, reason) {
		rec.Reasons = append(rec.Reasons, reason)
	}

	ttl := 3 * e.halfLife
	if err := e.store.PutScore(ip, rec, ttl); err != nil {
		return 0, fmt.Errorf("reputation: put %q: %w", ip, err)
	}
	return rec.Score, nil
}

// Decay reads ip's current score, applies time decay, persists it, and returns the result.
// Returns 0 and nil if ip is not in the store.
func (e *Engine) Decay(ip string) (float64, error) {
	rec, err := e.store.GetScore(ip)
	if err != nil {
		return 0, fmt.Errorf("reputation: get %q: %w", ip, err)
	}
	if rec.LastSeen.IsZero() {
		return 0, nil
	}
	rec.Score = DecayScore(rec.Score, rec.LastSeen, time.Now(), e.halfLife)
	ttl := 3 * e.halfLife
	if err := e.store.PutScore(ip, rec, ttl); err != nil {
		return 0, fmt.Errorf("reputation: put %q: %w", ip, err)
	}
	return rec.Score, nil
}

// GetRecord returns the raw ScoreRecord for ip (zero value if not found).
func (e *Engine) GetRecord(ip string) (store.ScoreRecord, error) {
	return e.store.GetScore(ip)
}
