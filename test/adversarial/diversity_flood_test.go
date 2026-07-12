//go:build adversarial

package adversarial

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
)

// TestSingleSubnetFloodScoresBelowBroad: for the SAME number of reports (20), a
// single subnet flooding them for one IP scores strictly below the same volume
// spread across 20 distinct subnets — the §4.2 Sybil-resistance property (a
// same-count flood cannot buy the breadth signal). Equal counts make the
// comparison robust to the logistic magnitude.
func TestSingleSubnetFloodScoresBelowBroad(t *testing.T) {
	now := time.Now()
	hl := 7 * 24 * time.Hour
	const n = 20
	flood := store.ScoreRecord{}
	for i := 0; i < n; i++ {
		flood = reputation.Accumulate(flood, reputation.Observation{
			Reason: "ssh-auth-success", ReporterID: "sybil", Group: "g", Subnet: "one", Trust: 0.9, Anchored: true,
		}, now, hl, 15, 0.15)
	}
	broad := store.ScoreRecord{}
	for i := 0; i < n; i++ {
		broad = reputation.Accumulate(broad, reputation.Observation{
			Reason: "ssh-auth-success", ReporterID: "r", Group: "g", Subnet: string(rune('a' + i)), Trust: 0.9, Anchored: true,
		}, now, hl, 15, 0.15)
	}
	if flood.Score >= broad.Score {
		t.Errorf("same-count single-subnet flood (%v) must score below broad multi-subnet (%v)", flood.Score, broad.Score)
	}
	if len(flood.SubnetsSeen) != 1 {
		t.Errorf("flood should register exactly one subnet, got %v", flood.SubnetsSeen)
	}
	if len(broad.SubnetsSeen) != n {
		t.Errorf("broad should register %d subnets, got %d", n, len(broad.SubnetsSeen))
	}
}
