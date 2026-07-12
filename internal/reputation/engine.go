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

// WeightFor returns the score-contribution weight for a reason code (the local
// weight table). Exported so the federated recompute can pick the highest-weight
// scenario as its vote reason (§8: recomputed under the consumer's own rules).
func WeightFor(reason string) float64 { return weightFor(reason) }

// Observation is one scoring input — a native event or a synthetic evidence vote.
type Observation struct {
	Reason     string
	ReporterID string
	Group      string
	Trust      float64
	Anchored   bool
	Subnet     string // originator's home subnet (diversity key); "" = untracked (solo / pre-E1)
}

// Accumulate applies obs to rec (lazily decayed to now) and returns the updated
// record. Pure: no store access. This is the single accumulation path — both
// Record (native events) and the federated recompute (internal/repquery) fold
// through it, so a federated score is computed under the same math as a local one.
func Accumulate(rec store.ScoreRecord, obs Observation, now time.Time, halfLife time.Duration, strangerCap, diversityRepeat float64) store.ScoreRecord {
	if !rec.LastSeen.IsZero() {
		rec.Score = DecayScore(rec.Score, rec.LastSeen, now, halfLife)
	}
	// Subnet-diversity weighting (§4.2): a repeat report from a subnet that has
	// already reported this IP counts for less; the first from a new subnet is
	// full. Empty subnet (solo / pre-E1) is never damped and never tracked.
	firstFromSubnet := obs.Subnet != "" && !containsString(rec.SubnetsSeen, obs.Subnet)
	divFactor := 1.0
	if obs.Subnet != "" && !firstFromSubnet {
		divFactor = diversityRepeat
	}
	contrib := obs.Trust * weightFor(obs.Reason) * (1 - rec.Score/100) * divFactor
	if !obs.Anchored {
		remaining := strangerCap - rec.StrangerContrib
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
	// Corroboration counts distinct ANCHORED Person groups only (spec Leitprinzip 8;
	// batch A P0-1) — strangers never satisfy a min_corroboration block rule.
	if obs.Anchored && obs.Group != "" && !containsString(rec.Groups, obs.Group) {
		rec.Groups = append(rec.Groups, obs.Group)
	}
	rec.Corroboration = len(rec.Groups)
	if !containsString(rec.ReporterIDs, obs.ReporterID) {
		rec.ReporterIDs = append(rec.ReporterIDs, obs.ReporterID)
	}
	if firstFromSubnet {
		rec.SubnetsSeen = append(rec.SubnetsSeen, obs.Subnet)
	}
	rec.LastSeen = now
	if rec.FirstSeen.IsZero() {
		rec.FirstSeen = now
	}
	if !containsString(rec.Reasons, obs.Reason) {
		rec.Reasons = append(rec.Reasons, obs.Reason)
	}
	return rec
}

// Engine computes IP reputation scores using lazy decay, logistic accumulation,
// Person-group corroboration, and a cumulative cap on stranger contributions
// (spec §4.2/§8; design docs/superpowers/specs/2026-06-12-social-trust-anchors-design.md).
type Engine struct {
	store           *store.BadgerStore
	halfLife        time.Duration
	strangerCap     float64
	diversityRepeat float64
}

// New creates an Engine backed by s. halfLife drives decay; strangerCap is the
// maximum total score un-anchored reporters can add to any single IP.
func New(s *store.BadgerStore, halfLife time.Duration, strangerCap, diversityRepeat float64) *Engine {
	return &Engine{store: s, halfLife: halfLife, strangerCap: strangerCap, diversityRepeat: diversityRepeat}
}

// Record applies one observation to ip's score and returns the new score.
// trust is the reporter's resolved weight (anchor weight, or stranger weight).
// group is the anchored Person's name ("" for strangers); anchored reports
// count as distinct corroboration votes per group, strangers share one capped
// bucket that never exceeds strangerCap score points in total. subnet is the
// originator's home subnet (diversity key, §4.2); "" leaves diversity untracked.
func (e *Engine) Record(ip, reason, reporterID string, trust float64, group, subnet string, anchored bool) (float64, error) {
	rec, err := e.store.GetScore(ip)
	if err != nil {
		return 0, fmt.Errorf("reputation: get %q: %w", ip, err)
	}
	rec = Accumulate(rec, Observation{
		Reason: reason, ReporterID: reporterID, Group: group, Subnet: subnet, Trust: trust, Anchored: anchored,
	}, time.Now(), e.halfLife, e.strangerCap, e.diversityRepeat)
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
