package reputation

import (
	"math"
	"time"
)

// DecayScore computes the decayed score using the formula:
//
//	score(t) = score₀ × exp(−ln2 × Δt / halfLife)
//
// Exported for unit testing. Engine.Decay calls this with time.Now().
func DecayScore(score float64, lastSeen, now time.Time, halfLife time.Duration) float64 {
	if score == 0 || halfLife <= 0 {
		return score
	}
	elapsed := now.Sub(lastSeen)
	if elapsed < 0 {
		elapsed = 0
	}
	elapsedSeconds := elapsed.Seconds()
	return score * math.Exp(-math.Log(2)*elapsedSeconds/halfLife.Seconds())
}
