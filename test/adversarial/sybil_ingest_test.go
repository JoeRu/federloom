//go:build adversarial

package adversarial

import (
	"fmt"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
)

// TestSybilFloodScoreCapped verifies that 50 distinct Sybil peers all reporting
// the same IP cannot push the reputation score above 100.  The logistic
// accumulation formula (score += trust * weight * (1 - score/100)) asymptotically
// approaches 100; this test confirms the cap is enforced.
func TestSybilFloodScoreCapped(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	engine := reputation.New(s, 7*24*time.Hour)

	const ip = "2.3.4.5"
	for i := 0; i < 50; i++ {
		peerID := fmt.Sprintf("sybil-peer-%d", i)
		if _, err := engine.Record(ip, "ssh-probe", peerID, 0.3); err != nil {
			t.Fatalf("Record[%d]: %v", i, err)
		}
	}

	rec, err := engine.GetRecord(ip)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}

	if rec.Score > 100.0 {
		t.Errorf("score exceeded 100: got %.4f", rec.Score)
	}
	if rec.Score <= 0 {
		t.Errorf("score should be > 0 after 50 reports, got %.4f", rec.Score)
	}
	if rec.Corroboration != 50 {
		t.Errorf("corroboration: want 50 distinct reporters, got %d", rec.Corroboration)
	}
}

// TestSybilFloodHighTrustCapped verifies the cap holds even when each Sybil peer
// reports with maximum local trust (1.0) and the highest-weight reason
// (ssh-auth-success, weight=40).  The score will be near 100 after just a few
// records; after 50 it must still be <= 100.
func TestSybilFloodHighTrustCapped(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	engine := reputation.New(s, 7*24*time.Hour)

	const ip = "3.4.5.6"
	for i := 0; i < 50; i++ {
		peerID := fmt.Sprintf("peer-%d", i)
		if _, err := engine.Record(ip, "ssh-auth-success", peerID, 1.0); err != nil {
			t.Fatalf("Record[%d]: %v", i, err)
		}
	}

	rec, err := engine.GetRecord(ip)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}

	if rec.Score > 100.0 {
		t.Errorf("score exceeded 100 with high-trust flood: got %.4f", rec.Score)
	}
	if rec.Score <= 0 {
		t.Errorf("score should be > 0 after 50 high-trust reports, got %.4f", rec.Score)
	}
}
