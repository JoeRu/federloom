//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
)

// TestEngineRecordAndGetScore verifies that a single Record call persists a
// score, sets corroboration to 1, and records the reason.
func TestEngineRecordAndGetScore(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()

	engine := reputation.New(s, 7*24*time.Hour, 15)

	if _, err := engine.Record("1.2.3.4", "ssh-auth-bruteforce", "peer1", 1.0, "peer1", true); err != nil {
		t.Fatalf("engine.Record: %v", err)
	}

	rec, err := engine.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("engine.GetRecord: %v", err)
	}

	if rec.Score <= 0 {
		t.Errorf("Score = %v, want > 0", rec.Score)
	}
	if rec.Corroboration != 1 {
		t.Errorf("Corroboration = %d, want 1", rec.Corroboration)
	}
	if len(rec.Reasons) != 1 {
		t.Errorf("len(Reasons) = %d, want 1", len(rec.Reasons))
	} else if rec.Reasons[0] != "ssh-auth-bruteforce" {
		t.Errorf("Reasons[0] = %q, want %q", rec.Reasons[0], "ssh-auth-bruteforce")
	}
}

// TestEngineDecayReducesScore verifies that after two half-lives the score
// drops below half its original value (well below 20 out of an initial ~40).
func TestEngineDecayReducesScore(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()

	// 1-second half-life so we can observe decay quickly.
	engine := reputation.New(s, time.Second, 15)

	// ssh-auth-success has weight 40; first record gives score ≈ 40*(1-0/100) = 40.
	if _, err := engine.Record("1.2.3.4", "ssh-auth-success", "peer1", 1.0, "peer1", true); err != nil {
		t.Fatalf("engine.Record: %v", err)
	}

	// Sleep two half-lives → score should decay to ~40 * 0.25 = 10.
	time.Sleep(2 * time.Second)

	if _, err := engine.Decay("1.2.3.4"); err != nil {
		t.Fatalf("engine.Decay: %v", err)
	}

	rec, err := engine.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("engine.GetRecord: %v", err)
	}

	if rec.Score >= 20 {
		t.Errorf("Score = %v after 2 half-lives, want < 20", rec.Score)
	}
}

// TestEngineMultipleReportersCorroboration verifies that three distinct
// reporters each increment Corroboration and that a duplicate reporter is
// deduplicated.
func TestEngineMultipleReportersCorroboration(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()

	engine := reputation.New(s, 7*24*time.Hour, 15)

	for _, reporter := range []string{"peer1", "peer2", "peer3"} {
		if _, err := engine.Record("1.2.3.4", "ssh-probe", reporter, 1.0, reporter, true); err != nil {
			t.Fatalf("engine.Record(%s): %v", reporter, err)
		}
	}

	rec, err := engine.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("engine.GetRecord: %v", err)
	}

	if rec.Corroboration != 3 {
		t.Errorf("Corroboration = %d after 3 distinct reporters, want 3", rec.Corroboration)
	}
	if len(rec.ReporterIDs) != 3 {
		t.Errorf("len(ReporterIDs) = %d, want 3", len(rec.ReporterIDs))
	}

	// Duplicate reporter — corroboration must not increase.
	if _, err := engine.Record("1.2.3.4", "ssh-probe", "peer1", 1.0, "peer1", true); err != nil {
		t.Fatalf("engine.Record(peer1 duplicate): %v", err)
	}

	rec, err = engine.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("engine.GetRecord after duplicate: %v", err)
	}

	if rec.Corroboration != 3 {
		t.Errorf("Corroboration = %d after duplicate peer1, want 3 (no change)", rec.Corroboration)
	}
}
