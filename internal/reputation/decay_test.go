package reputation_test

import (
	"math"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/reputation"
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
