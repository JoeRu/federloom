package reputation_test

import (
	"math"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/reputation"
)

func TestDecayAtZeroElapsed(t *testing.T) {
	now := time.Now()
	got := reputation.DecayScore(100, now, now, 7*24*time.Hour)
	if math.Abs(got-100) > 0.001 {
		t.Errorf("expected ~100, got %v", got)
	}
}

func TestDecayAtOneHalfLife(t *testing.T) {
	halfLife := 7 * 24 * time.Hour
	lastSeen := time.Now().Add(-halfLife)
	got := reputation.DecayScore(100, lastSeen, time.Now(), halfLife)
	if math.Abs(got-50) > 0.5 {
		t.Errorf("expected ~50 at one half-life, got %v", got)
	}
}

func TestDecayAtTwoHalfLives(t *testing.T) {
	halfLife := 7 * 24 * time.Hour
	lastSeen := time.Now().Add(-2 * halfLife)
	got := reputation.DecayScore(100, lastSeen, time.Now(), halfLife)
	if math.Abs(got-25) > 0.5 {
		t.Errorf("expected ~25 at two half-lives, got %v", got)
	}
}

func TestDecayZeroScoreStaysZero(t *testing.T) {
	lastSeen := time.Now().Add(-24 * time.Hour)
	got := reputation.DecayScore(0, lastSeen, time.Now(), 7*24*time.Hour)
	if got != 0 {
		t.Errorf("expected 0, got %v", got)
	}
}

// TestDecayScoreFutureLastSeenDoesNotGrow guards against a federated peer
// supplying a future WindowLast (e.g. EvidenceAggregate.WindowLast): elapsed
// time must be floored at zero, never letting the exponential become a
// growth factor that inflates the score past its input value.
func TestDecayScoreFutureLastSeenDoesNotGrow(t *testing.T) {
	now := time.Now()
	future := now.Add(30 * 24 * time.Hour)
	got := reputation.DecayScore(100, future, now, 7*24*time.Hour)
	if math.Abs(got-100) > 0.001 {
		t.Errorf("future lastSeen must not grow score: expected ~100, got %v", got)
	}
}
