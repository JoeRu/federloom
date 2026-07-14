package reputation_test

import (
	"fmt"
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
	return reputation.New(s, 7*24*time.Hour, cap, 0.15, 10)
}

// TestStrangerContributionCapped: strangers can never add more than the cap,
// no matter how many of them report (spec §4.2 / design "capped strangers").
func TestStrangerContributionCapped(t *testing.T) {
	e := openEngineCap(t, 15)
	var last float64
	for i := 0; i < 100; i++ {
		var err error
		last, err = e.Record("192.0.2.1", "ssh-auth-success", "stranger", 1.0, "", "", false)
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
		if _, err := e.Record("192.0.2.1", "ssh-auth-success", "s1", 1.0, "", "", false); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	before, _ := e.GetRecord("192.0.2.1")
	if _, err := e.Record("192.0.2.1", "ssh-auth-success", "s2", 1.0, "", "", false); err != nil {
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
		score, err = e.Record("192.0.2.2", "ssh-auth-success", "joA", 0.9, "jo", "", true)
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
		if _, err := e.Record("192.0.2.3", "ssh-probe", peerID, 0.9, "jo", "", true); err != nil {
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
		if _, err := e.Record("192.0.2.4", "ssh-probe", peerID, 0.3, "", "", false); err != nil {
			t.Fatalf("Record %s: %v", peerID, err)
		}
	}
	if _, err := e.Record("192.0.2.4", "ssh-probe", "joA", 0.9, "jo", "", true); err != nil {
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
		if _, err := e.Record("192.0.2.5", "ssh-auth-success", "stranger", 1.0, "", "", false); err != nil {
			t.Fatalf("stranger Record: %v", err)
		}
	}
	saturated, _ := e.GetRecord("192.0.2.5")
	if saturated.Score > 15.0001 {
		t.Fatalf("precondition: strangers exceeded cap (%v)", saturated.Score)
	}
	score, err := e.Record("192.0.2.5", "ssh-auth-success", "joA", 0.9, "jo", "", true)
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
	eng := reputation.New(s, 7*24*time.Hour, 15, 0.15, 10)

	// One un-anchored (stranger) report: anchored=false, group="".
	if _, err := eng.Record("203.0.113.7", "ssh-post-auth-command", "stranger-1", 0.3, "", "", false); err != nil {
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
	eng := reputation.New(s, 7*24*time.Hour, 15, 0.15, 10)

	// Two distinct anchored groups + a stranger on the same IP.
	_, _ = eng.Record("203.0.113.8", "ssh-probe", "peerA", 0.9, "alice", "", true)
	_, _ = eng.Record("203.0.113.8", "ssh-probe", "peerB", 0.9, "bob", "", true)
	_, _ = eng.Record("203.0.113.8", "ssh-probe", "peerC", 0.3, "", "", false)

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
			score, err := e.Record("192.0.2.10", tc.reason, "self", 1.0, "self", "", true)
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
	}, now, 7*24*time.Hour, 15, 0.15)
	if rec.Score < 1.79 || rec.Score > 1.81 {
		t.Errorf("Score = %v, want ~1.8", rec.Score)
	}
	if len(rec.Groups) != 1 || rec.Groups[0] != "jo" || rec.Corroboration != 1 {
		t.Errorf("anchored group not recorded: %+v", rec)
	}
	// Stranger contribution is capped at strangerCap.
	rec2 := store.ScoreRecord{}
	for i := 0; i < 100; i++ {
		rec2 = reputation.Accumulate(rec2, reputation.Observation{Reason: "smtp-spamtrap", ReporterID: "s", Trust: 0.3, Anchored: false}, now, 7*24*time.Hour, 15, 0.15)
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

func TestAccumulateSubnetDiversity(t *testing.T) {
	now := time.Now()
	hl := 7 * 24 * time.Hour
	// Ten reports from ONE subnet: first full, nine damped.
	one := store.ScoreRecord{}
	for i := 0; i < 10; i++ {
		one = reputation.Accumulate(one, reputation.Observation{Reason: "ssh-probe", ReporterID: "r", Group: "g", Trust: 0.9, Anchored: true, Subnet: "a"}, now, hl, 15, 0.15)
	}
	// Ten reports from TEN distinct subnets: all full.
	ten := store.ScoreRecord{}
	for i := 0; i < 10; i++ {
		ten = reputation.Accumulate(ten, reputation.Observation{Reason: "ssh-probe", ReporterID: "r", Group: "g", Trust: 0.9, Anchored: true, Subnet: string(rune('a' + i))}, now, hl, 15, 0.15)
	}
	if !(ten.Score > one.Score) {
		t.Errorf("ten subnets (%v) must outscore one subnet (%v)", ten.Score, one.Score)
	}
	if len(one.SubnetsSeen) != 1 {
		t.Errorf("one-subnet SubnetsSeen = %v, want len 1", one.SubnetsSeen)
	}
	if len(ten.SubnetsSeen) != 10 {
		t.Errorf("ten-subnet SubnetsSeen = %v, want len 10", ten.SubnetsSeen)
	}
	// Empty subnet reproduces today's math (factor 1.0, no SubnetsSeen tracking).
	empty := reputation.Accumulate(store.ScoreRecord{}, reputation.Observation{Reason: "ssh-probe", ReporterID: "r", Group: "g", Trust: 0.9, Anchored: true, Subnet: ""}, now, hl, 15, 0.15)
	if empty.Score < 1.79 || empty.Score > 1.81 || len(empty.SubnetsSeen) != 0 {
		t.Errorf("empty-subnet obs must score ~1.8 with no SubnetsSeen, got %v / %v", empty.Score, empty.SubnetsSeen)
	}
}

func TestApplyDisputeDiversityWeighted(t *testing.T) {
	now := time.Now()
	hl := 7 * 24 * time.Hour
	// Start from a high score (as if reported bad).
	base := store.ScoreRecord{Score: 90, LastSeen: now, FirstSeen: now}

	// Ten disputes from ONE subnet: first full, rest damped → small reduction.
	one := base
	for i := 0; i < 10; i++ {
		one = reputation.ApplyDispute(one, reputation.Observation{ReporterID: "d", Subnet: "a", Trust: 0.9, Anchored: true}, now, hl, 10, 15, 0.15)
	}
	// Ten disputes from TEN subnets: full each → large reduction.
	ten := base
	for i := 0; i < 10; i++ {
		ten = reputation.ApplyDispute(ten, reputation.Observation{ReporterID: "d", Subnet: string(rune('a' + i)), Trust: 0.9, Anchored: true}, now, hl, 10, 15, 0.15)
	}
	if !(ten.Score < one.Score) {
		t.Errorf("ten disputing subnets (%v) must reduce more than one (%v)", ten.Score, one.Score)
	}
	if len(one.DisputeSubnetsSeen) != 1 || len(ten.DisputeSubnetsSeen) != 10 {
		t.Errorf("dispute subnets tracked wrong: %d / %d", len(one.DisputeSubnetsSeen), len(ten.DisputeSubnetsSeen))
	}
	// Score floors at 0.
	floored := store.ScoreRecord{Score: 5, LastSeen: now}
	for i := 0; i < 5; i++ {
		floored = reputation.ApplyDispute(floored, reputation.Observation{ReporterID: "d", Subnet: string(rune('a' + i)), Trust: 1, Anchored: true}, now, hl, 50, 15, 0.15)
	}
	if floored.Score < 0 {
		t.Errorf("score must floor at 0, got %v", floored.Score)
	}
	// Dispute diversity is SEPARATE from report diversity (SubnetsSeen untouched).
	if len(ten.SubnetsSeen) != 0 {
		t.Errorf("ApplyDispute must not touch SubnetsSeen, got %v", ten.SubnetsSeen)
	}
}

// TestApplyDisputeStrangerCapBounded proves two things:
// (a) the Sybil bound — a stranger dispute-flood fanned out across many
// DISTINCT subnets (worst case: no subnet damping) cannot reduce a score by
// more than strangerCap in total.
// (b) the Fix-1 correction — an ANCHORED dispute must not consume the
// stranger DisputeContrib budget, so a subsequent stranger dispute still has
// room to reduce the score further.
func TestApplyDisputeStrangerCapBounded(t *testing.T) {
	now := time.Now()
	hl := 7 * 24 * time.Hour
	const disputeWeight = 10
	const strangerCap = 15
	const diversityRepeat = 0.15

	// (a) 100 stranger disputes across 100 distinct subnets — no subnet is
	// repeated, so divFactor is always 1 (the worst case for the cap).
	rec := store.ScoreRecord{Score: 90, LastSeen: now, FirstSeen: now}
	for i := 0; i < 100; i++ {
		rec = reputation.ApplyDispute(rec, reputation.Observation{
			ReporterID: "flooder",
			Subnet:     fmt.Sprintf("subnet-%d", i),
			Trust:      1.0,
			Anchored:   false,
		}, now, hl, disputeWeight, strangerCap, diversityRepeat)
	}
	const epsilon = 0.1
	minScore := 90 - strangerCap - epsilon
	if rec.Score < minScore {
		t.Errorf("100-subnet stranger dispute flood reduced score to %v, want >= %v (strangerCap=%v)", rec.Score, minScore, strangerCap)
	}
	if len(rec.DisputeSubnetsSeen) != 0 {
		t.Error("stranger disputes must not count toward dispute diversity")
	}

	// (b) An anchored dispute must not exhaust the stranger DisputeContrib
	// budget. Apply one big anchored dispute (large disputeWeight, full trust),
	// then a stranger dispute on a fresh subnet — it must still reduce the
	// score further. Against the pre-fix code (DisputeContrib += reduction
	// outside the !Anchored block), the anchored dispute below pushes
	// DisputeContrib to 45 (> strangerCap 15), so the stranger dispute's
	// `remaining` clamps to 0 and it becomes a no-op — this assertion would fail.
	base := store.ScoreRecord{Score: 90, LastSeen: now, FirstSeen: now}
	afterAnchored := reputation.ApplyDispute(base, reputation.Observation{
		ReporterID: "anchor",
		Subnet:     "anchored-subnet",
		Trust:      1.0,
		Anchored:   true,
	}, now, hl, 50, strangerCap, diversityRepeat)
	if !(afterAnchored.Score < base.Score) {
		t.Fatalf("anchored dispute did not reduce score: before %v after %v", base.Score, afterAnchored.Score)
	}

	afterStranger := reputation.ApplyDispute(afterAnchored, reputation.Observation{
		ReporterID: "stranger",
		Subnet:     "stranger-subnet",
		Trust:      1.0,
		Anchored:   false,
	}, now, hl, disputeWeight, strangerCap, diversityRepeat)
	if !(afterStranger.Score < afterAnchored.Score) {
		t.Errorf("stranger dispute after a large anchored dispute must still reduce the score (DisputeContrib must not be exhausted by anchored): before %v after %v (DisputeContrib=%v)", afterAnchored.Score, afterStranger.Score, afterAnchored.DisputeContrib)
	}
}

// TestApplyDisputeStrangersDontCountSubnets proves the Sybil-fabricated-subnet
// fix: obs.Subnet is attacker-controlled and unsigned, so a single unanchored
// node claiming 5 DISTINCT fabricated SubnetIDs must never grow
// DisputeSubnetsSeen (the count that gates the materialised-block unblock in
// internal/node.maybeUnblockDisputed). The score may still be reduced, but
// only up to the stranger cap.
func TestApplyDisputeStrangersDontCountSubnets(t *testing.T) {
	now := time.Now()
	hl := 7 * 24 * time.Hour
	const disputeWeight = 10
	const strangerCap = 15
	const diversityRepeat = 0.15

	rec := store.ScoreRecord{Score: 90, LastSeen: now, FirstSeen: now}
	for i := 0; i < 5; i++ {
		rec = reputation.ApplyDispute(rec, reputation.Observation{
			ReporterID: "stranger",
			Subnet:     fmt.Sprintf("fake-subnet-%d", i), // fabricated, distinct
			Trust:      1.0,
			Anchored:   false,
		}, now, hl, disputeWeight, strangerCap, diversityRepeat)
	}
	if len(rec.DisputeSubnetsSeen) != 0 {
		t.Errorf("stranger disputes across %d fabricated distinct subnets must not fabricate diversity: DisputeSubnetsSeen=%v", 5, rec.DisputeSubnetsSeen)
	}
	const epsilon = 0.1
	minScore := 90 - strangerCap - epsilon
	if rec.Score < minScore {
		t.Errorf("stranger flood reduced score to %v, want >= %v (strangerCap=%v)", rec.Score, minScore, strangerCap)
	}
}
