//go:build adversarial

package adversarial

import (
	"fmt"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
)

// TestSybilFloodScoreCapped verifies that 50 Sybil strangers all reporting the
// same IP are score-capped at the stranger cap and count as a single
// corroboration vote (spec §4.2, social-trust design).  Un-anchored, ungrouped
// reporters share one stranger slot, so neither score nor corroboration can be
// inflated by spinning up more identities.
func TestSybilFloodScoreCapped(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	engine := reputation.New(s, 7*24*time.Hour, 15, 0.15)

	const ip = "2.3.4.5"
	for i := 0; i < 50; i++ {
		peerID := fmt.Sprintf("sybil-peer-%d", i)
		if _, err := engine.Record(ip, "ssh-probe", peerID, 0.3, "", "", false); err != nil {
			t.Fatalf("Record[%d]: %v", i, err)
		}
	}

	rec, err := engine.GetRecord(ip)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}

	if rec.Score > 15.0001 {
		t.Errorf("stranger flood exceeded cap: got %.4f, want <= 15", rec.Score)
	}
	if rec.Score <= 0 {
		t.Errorf("score should be > 0 after 50 reports, got %.4f", rec.Score)
	}
	if rec.Corroboration != 0 {
		t.Errorf("corroboration: strangers must not corroborate, got %d (want 0)", rec.Corroboration)
	}
}

// TestSybilFloodHighTrustCapped verifies the stranger cap holds even when each
// Sybil peer claims maximum trust (1.0) and the highest-weight reason
// (ssh-auth-success, weight=40).  An un-anchored reporter is still a stranger no
// matter what trust it self-asserts, so the flood is capped at the stranger cap
// and counts as a single corroboration vote (spec §4.2, social-trust design).
func TestSybilFloodHighTrustCapped(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	engine := reputation.New(s, 7*24*time.Hour, 15, 0.15)

	const ip = "3.4.5.6"
	for i := 0; i < 50; i++ {
		peerID := fmt.Sprintf("peer-%d", i)
		if _, err := engine.Record(ip, "ssh-auth-success", peerID, 1.0, "", "", false); err != nil {
			t.Fatalf("Record[%d]: %v", i, err)
		}
	}

	rec, err := engine.GetRecord(ip)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}

	if rec.Score > 15.0001 {
		t.Errorf("stranger flood exceeded cap: got %.4f, want <= 15", rec.Score)
	}
	if rec.Score <= 0 {
		t.Errorf("score should be > 0 after 50 reports, got %.4f", rec.Score)
	}
	if rec.Corroboration != 0 {
		t.Errorf("corroboration: strangers must not corroborate, got %d (want 0)", rec.Corroboration)
	}
}
