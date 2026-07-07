package reputation

import (
	"fmt"
	"time"

	"github.com/JoeRu/federloom/internal/store"
)

// reportWeight maps event reason to score contribution weight.
var reportWeight = map[string]float64{
	"ssh-auth-success":      40,
	"ssh-auth-bruteforce":   10,
	"ssh-post-auth-command": 10,
	"ssh-probe":             2,
	"ssh-unknown":           2,
	// SMTP/IMAP — mirrors SSH weights; spamtrap is highest (zero-FP on production)
	"smtp-auth-bruteforce": 10,
	"smtp-auth-success":    40,
	"smtp-probe":           2,
	"smtp-spamtrap":        50,
	"imap-auth-bruteforce": 10,
	"imap-auth-success":    30,
	"imap-probe":           2,
	"pop3-auth-bruteforce": 10,
}

func weightFor(reason string) float64 {
	if w, ok := reportWeight[reason]; ok {
		return w
	}
	return 2
}

// Engine computes IP reputation scores using lazy decay, logistic accumulation,
// Person-group corroboration, and a cumulative cap on stranger contributions
// (spec §4.2/§8; design docs/superpowers/specs/2026-06-12-social-trust-anchors-design.md).
type Engine struct {
	store       *store.BadgerStore
	halfLife    time.Duration
	strangerCap float64
}

// New creates an Engine backed by s. halfLife drives decay; strangerCap is the
// maximum total score un-anchored reporters can add to any single IP.
func New(s *store.BadgerStore, halfLife time.Duration, strangerCap float64) *Engine {
	return &Engine{store: s, halfLife: halfLife, strangerCap: strangerCap}
}

// Record applies one observation to ip's score and returns the new score.
// trust is the reporter's resolved weight (anchor weight, or stranger weight).
// group is the anchored Person's name ("" for strangers); anchored reports
// count as distinct corroboration votes per group, strangers share one capped
// bucket that never exceeds strangerCap score points in total.
func (e *Engine) Record(ip, reason, reporterID string, trust float64, group string, anchored bool) (float64, error) {
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
	contrib := trust * weightFor(reason) * (1 - rec.Score/100)
	if !anchored {
		remaining := e.strangerCap - rec.StrangerContrib
		if remaining < 0 {
			remaining = 0
		}
		if contrib > remaining {
			contrib = remaining
		}
		rec.StrangerContrib += contrib
		rec.StrangerSeen = true
	}
	rec.Score += contrib
	if rec.Score > 100 {
		rec.Score = 100
	}

	// Corroboration counts distinct ANCHORED Person groups only. Strangers are
	// deliberately excluded so a single un-anchored remote reporter can never
	// satisfy a min_corroboration block rule (spec Leitprinzip 8; batch A P0-1).
	// StrangerSeen/StrangerContrib still bound the stranger *score* (cap 15).
	if anchored && group != "" && !containsString(rec.Groups, group) {
		rec.Groups = append(rec.Groups, group)
	}
	rec.Corroboration = len(rec.Groups)

	// Audit trail and metadata.
	if !containsString(rec.ReporterIDs, reporterID) {
		rec.ReporterIDs = append(rec.ReporterIDs, reporterID)
	}
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
