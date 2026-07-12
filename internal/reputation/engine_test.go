package reputation_test

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
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

// TestCorroborationStrangersNeverCount: any number of strangers contribute
// zero corroboration votes; only the anchored Person group counts (batch A
// P0-1: strangers must never satisfy a min_corroboration block rule).
func TestCorroborationStrangersNeverCount(t *testing.T) {
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
	if rec.Corroboration != 1 {
		t.Errorf("corroboration = %d, want 1 (1 Person group; strangers never corroborate)", rec.Corroboration)
	}
}

// TestAnchoredAddsScoreOnTopOfSaturatedStrangers: once strangers have pinned the
// score at the cap, an anchored reporter still raises it past the cap — the
// stranger ceiling must not bound anchored contributions (spec §4.2).
func TestAnchoredAddsScoreOnTopOfSaturatedStrangers(t *testing.T) {
	e := openEngineCap(t, 15)
	for i := 0; i < 50; i++ {
		if _, err := e.Record("192.0.2.5", "ssh-auth-success", "stranger", 1.0, "", false); err != nil {
			t.Fatalf("stranger Record: %v", err)
		}
	}
	saturated, _ := e.GetRecord("192.0.2.5")
	if saturated.Score > 15.0001 {
		t.Fatalf("precondition: strangers exceeded cap (%v)", saturated.Score)
	}
	score, err := e.Record("192.0.2.5", "ssh-auth-success", "joA", 0.9, "jo", true)
	if err != nil {
		t.Fatalf("anchored Record: %v", err)
	}
	if score <= saturated.Score {
		t.Errorf("anchored reporter added no score over saturated strangers: %v -> %v", saturated.Score, score)
	}
}

// TestStrangerDoesNotCountAsCorroboration verifies that a lone un-anchored
// reporter never bumps Corroboration, so it can never satisfy a
// min_corroboration:1 block rule (spec Leitprinzip 8; batch A P0-1).
func TestStrangerDoesNotCountAsCorroboration(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	eng := reputation.New(s, 7*24*time.Hour, 15)

	// One un-anchored (stranger) report: anchored=false, group="".
	if _, err := eng.Record("203.0.113.7", "ssh-post-auth-command", "stranger-1", 0.3, "", false); err != nil {
		t.Fatalf("Record: %v", err)
	}
	rec, err := eng.GetRecord("203.0.113.7")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Corroboration != 0 {
		t.Errorf("stranger must not corroborate: Corroboration=%d, want 0", rec.Corroboration)
	}
	if !rec.StrangerSeen {
		t.Error("StrangerSeen should still be true after a stranger report")
	}
}

// TestAnchoredGroupsCountAsCorroboration verifies that only distinct anchored
// Person groups count toward Corroboration; a stranger on the same IP adds
// nothing.
func TestAnchoredGroupsCountAsCorroboration(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	eng := reputation.New(s, 7*24*time.Hour, 15)

	// Two distinct anchored groups + a stranger on the same IP.
	_, _ = eng.Record("203.0.113.8", "ssh-probe", "peerA", 0.9, "alice", true)
	_, _ = eng.Record("203.0.113.8", "ssh-probe", "peerB", 0.9, "bob", true)
	_, _ = eng.Record("203.0.113.8", "ssh-probe", "peerC", 0.3, "", false)

	rec, err := eng.GetRecord("203.0.113.8")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Corroboration != 2 {
		t.Errorf("two anchored groups (+1 stranger) must yield Corroboration=2, got %d", rec.Corroboration)
	}
}

// TestSMTPWeightsHigherThanDefault verifies SMTP/IMAP events score above the
// 2-point default so a mailcow node reacts faster than it would to generic reasons.
func TestSMTPWeightsHigherThanDefault(t *testing.T) {
	cases := []struct {
		reason  string
		wantMin float64
	}{
		{"smtp-auth-bruteforce", 9},
		{"smtp-spamtrap", 45},
		{"imap-auth-bruteforce", 9},
		{"pop3-auth-bruteforce", 9},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			e := openEngineCap(t, 15) // helper already defined in this file
			score, err := e.Record("192.0.2.10", tc.reason, "self", 1.0, "self", true)
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			if score < tc.wantMin {
				t.Errorf("reason=%q: score=%.2f, want >= %.2f", tc.reason, score, tc.wantMin)
			}
		})
	}
}

func TestAccumulateMatchesKnownContribution(t *testing.T) {
	// One anchored ssh-probe (weight 2) at trust 0.9 onto an empty record:
	// contrib = 0.9 * 2 * (1 - 0/100) = 1.8.
	now := time.Now()
	rec := reputation.Accumulate(store.ScoreRecord{}, reputation.Observation{
		Reason: "ssh-probe", ReporterID: "r1", Group: "jo", Trust: 0.9, Anchored: true,
	}, now, 7*24*time.Hour, 15)
	if rec.Score < 1.79 || rec.Score > 1.81 {
		t.Errorf("Score = %v, want ~1.8", rec.Score)
	}
	if len(rec.Groups) != 1 || rec.Groups[0] != "jo" || rec.Corroboration != 1 {
		t.Errorf("anchored group not recorded: %+v", rec)
	}
	// Stranger contribution is capped at strangerCap.
	rec2 := store.ScoreRecord{}
	for i := 0; i < 100; i++ {
		rec2 = reputation.Accumulate(rec2, reputation.Observation{Reason: "smtp-spamtrap", ReporterID: "s", Trust: 0.3, Anchored: false}, now, 7*24*time.Hour, 15)
	}
	if rec2.Score > 15.001 || !rec2.StrangerSeen {
		t.Errorf("stranger cap not honored: score=%v", rec2.Score)
	}
	if len(rec2.Groups) != 0 {
		t.Errorf("stranger must not add groups: %+v", rec2.Groups)
	}
}

func TestWeightForExported(t *testing.T) {
	if reputation.WeightFor("ssh-auth-success") != 40 || reputation.WeightFor("unknown-reason") != 2 {
		t.Errorf("WeightFor: got %v/%v", reputation.WeightFor("ssh-auth-success"), reputation.WeightFor("unknown-reason"))
	}
}
