package reputation_test

import (
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
)

func openEngineCap(t *testing.T, cap float64) *reputation.Engine {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return reputation.New(s, 7*24*time.Hour, cap)
}

// TestStrangerContributionCapped: strangers can never add more than the cap,
// no matter how many of them report (spec §4.2 / design "capped strangers").
func TestStrangerContributionCapped(t *testing.T) {
	e := openEngineCap(t, 15)
	var last float64
	for i := 0; i < 100; i++ {
		var err error
		last, err = e.Record("192.0.2.1", "ssh-auth-success", "stranger", 1.0, "", false)
		if err != nil {
			t.Fatalf("Record[%d]: %v", i, err)
		}
	}
	if last > 15.0001 {
		t.Errorf("stranger-driven score = %v, want <= cap 15", last)
	}
}

// TestStrangerAtCapAddsZero: once at the cap, further stranger reports add nothing.
func TestStrangerAtCapAddsZero(t *testing.T) {
	e := openEngineCap(t, 15)
	for i := 0; i < 50; i++ {
		if _, err := e.Record("192.0.2.1", "ssh-auth-success", "s1", 1.0, "", false); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	before, _ := e.GetRecord("192.0.2.1")
	if _, err := e.Record("192.0.2.1", "ssh-auth-success", "s2", 1.0, "", false); err != nil {
		t.Fatalf("Record at cap: %v", err)
	}
	after, _ := e.GetRecord("192.0.2.1")
	if after.Score > before.Score+0.0001 {
		t.Errorf("score grew past cap: %v -> %v", before.Score, after.Score)
	}
}

// TestAnchoredNotCapped: anchored reporters are unaffected by the stranger cap.
func TestAnchoredNotCapped(t *testing.T) {
	e := openEngineCap(t, 15)
	var score float64
	for i := 0; i < 10; i++ {
		var err error
		score, err = e.Record("192.0.2.2", "ssh-auth-success", "joA", 0.9, "jo", true)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if score <= 15 {
		t.Errorf("anchored score = %v, want > stranger cap 15", score)
	}
}

// TestCorroborationCountsGroupsNotPeers: 3 machines of one Person = 1 vote.
func TestCorroborationCountsGroupsNotPeers(t *testing.T) {
	e := openEngineCap(t, 15)
	for _, peerID := range []string{"joA", "joB", "joC"} {
		if _, err := e.Record("192.0.2.3", "ssh-probe", peerID, 0.9, "jo", true); err != nil {
			t.Fatalf("Record %s: %v", peerID, err)
		}
	}
	rec, _ := e.GetRecord("192.0.2.3")
	if rec.Corroboration != 1 {
		t.Errorf("corroboration = %d, want 1 (single Person group)", rec.Corroboration)
	}
	if len(rec.ReporterIDs) != 3 {
		t.Errorf("ReporterIDs = %v, want 3 entries (audit trail)", rec.ReporterIDs)
	}
}

// TestCorroborationStrangersCountOnce: all strangers together are one vote.
func TestCorroborationStrangersCountOnce(t *testing.T) {
	e := openEngineCap(t, 15)
	for _, peerID := range []string{"s1", "s2", "s3"} {
		if _, err := e.Record("192.0.2.4", "ssh-probe", peerID, 0.3, "", false); err != nil {
			t.Fatalf("Record %s: %v", peerID, err)
		}
	}
	if _, err := e.Record("192.0.2.4", "ssh-probe", "joA", 0.9, "jo", true); err != nil {
		t.Fatalf("Record anchored: %v", err)
	}
	rec, _ := e.GetRecord("192.0.2.4")
	if rec.Corroboration != 2 {
		t.Errorf("corroboration = %d, want 2 (1 Person group + 1 stranger bucket)", rec.Corroboration)
	}
}
