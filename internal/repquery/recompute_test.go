package repquery

import (
	"math"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

func TestRecordFromEvidenceRecomputesLocally(t *testing.T) {
	now := time.Now().UTC()
	ev := proto.EvidenceAggregate{
		IP:               "203.0.113.7",
		Scenarios:        []string{"ssh-probe", "ssh-auth-success"}, // max weight = ssh-auth-success (40)
		WindowFirst:      now.Add(-time.Hour),
		WindowLast:       now,
		DiversityBuckets: map[string]int{"groups": 3, "reporters": 9},
		StrangersPresent: false,
		EvidenceWeight:   1.0,
	}
	rec := RecordFromEvidence(ev, now, 7*24*time.Hour, 15, 0.5, 0.15, 10)

	// Score is recomputed locally and positive; more groups => higher.
	if rec.Score <= 0 {
		t.Fatalf("expected positive recomputed score, got %v", rec.Score)
	}
	// CRITICAL INVARIANT: a federated answer never manufactures anchored corroboration.
	if len(rec.Groups) != 0 || rec.Corroboration != 0 || len(rec.ReporterIDs) != 0 || rec.StrangerSeen {
		t.Errorf("federated record leaked corroboration state: %+v", rec)
	}
	// Reasons carry the scenario union; window preserved.
	if len(rec.Reasons) != 2 || !rec.LastSeen.Equal(now) {
		t.Errorf("reasons/window wrong: %+v", rec)
	}

	// More groups => strictly higher score (diversity is carried across the import).
	evMore := ev
	evMore.DiversityBuckets = map[string]int{"groups": 6, "reporters": 12}
	recMore := RecordFromEvidence(evMore, now, 7*24*time.Hour, 15, 0.5, 0.15, 10)
	if recMore.Score <= rec.Score {
		t.Errorf("more groups should recompute higher: %v !> %v", recMore.Score, rec.Score)
	}
}

func TestRecordFromEvidenceNotFoundAndStrangerOnly(t *testing.T) {
	now := time.Now().UTC()
	// Zero WindowLast => empty record (not found).
	empty := RecordFromEvidence(proto.EvidenceAggregate{IP: "1.1.1.1"}, now, time.Hour, 15, 0.5, 0.15, 10)
	if !empty.LastSeen.IsZero() || empty.Score != 0 {
		t.Errorf("not-found evidence should yield empty record, got %+v", empty)
	}
	// Stranger-only evidence is bounded by the local stranger cap.
	strangerOnly := proto.EvidenceAggregate{
		IP: "2.2.2.2", Scenarios: []string{"smtp-spamtrap"}, WindowLast: now,
		DiversityBuckets: map[string]int{"groups": 0, "reporters": 5}, StrangersPresent: true, EvidenceWeight: 1.0,
	}
	rec := RecordFromEvidence(strangerOnly, now, 7*24*time.Hour, 15, 0.5, 0.15, 10)
	if rec.Score > 15.001 {
		t.Errorf("stranger-only evidence exceeded local cap: %v", rec.Score)
	}
	if len(rec.Groups) != 0 {
		t.Errorf("stranger-only must not add groups: %+v", rec.Groups)
	}
}

// TestRecordFromEvidenceFoldCapBounds proves an attacker-supplied "groups"
// bucket count can't drive an unbounded number of folds: a huge count must
// return promptly and score identically to the capped value (maxEvidenceFolds).
func TestRecordFromEvidenceFoldCapBounds(t *testing.T) {
	now := time.Now().UTC()
	base := proto.EvidenceAggregate{
		IP:               "203.0.113.8",
		Scenarios:        []string{"ssh-probe", "ssh-auth-success"},
		WindowFirst:      now.Add(-time.Hour),
		WindowLast:       now,
		StrangersPresent: false,
		EvidenceWeight:   1.0,
	}

	huge := base
	huge.DiversityBuckets = map[string]int{"groups": 1_000_000}

	capped := base
	capped.DiversityBuckets = map[string]int{"groups": 64}

	done := make(chan store.ScoreRecord, 1)
	go func() {
		done <- RecordFromEvidence(huge, now, 7*24*time.Hour, 15, 0.5, 0.15, 10)
	}()
	var recHuge store.ScoreRecord
	select {
	case recHuge = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RecordFromEvidence with groups=1_000_000 did not return promptly; fold cap not applied")
	}

	recCapped := RecordFromEvidence(capped, now, 7*24*time.Hour, 15, 0.5, 0.15, 10)

	if recHuge.Score != recCapped.Score {
		t.Errorf("groups=1_000_000 should score identically to capped groups=64: %v != %v", recHuge.Score, recCapped.Score)
	}
	// Groups-empty invariant still holds under the cap.
	if len(recHuge.Groups) != 0 || recHuge.Corroboration != 0 || len(recHuge.ReporterIDs) != 0 {
		t.Errorf("capped federated record leaked corroboration state: %+v", recHuge)
	}
}

// TestRecordFromEvidenceClampsWeight proves EvidenceWeight is clamped to
// [0,1] before it becomes trust: a weight >1 must not out-score weight==1,
// and a negative weight must clamp to 0 (zero contribution from anchored
// votes, so with no strangers present the score is 0).
func TestRecordFromEvidenceClampsWeight(t *testing.T) {
	now := time.Now().UTC()
	mk := func(weight float64) proto.EvidenceAggregate {
		return proto.EvidenceAggregate{
			IP:               "203.0.113.9",
			Scenarios:        []string{"ssh-probe", "ssh-auth-success"},
			WindowFirst:      now.Add(-time.Hour),
			WindowLast:       now,
			DiversityBuckets: map[string]int{"groups": 3},
			StrangersPresent: false,
			EvidenceWeight:   weight,
		}
	}

	recHigh := RecordFromEvidence(mk(5.0), now, 7*24*time.Hour, 15, 0.5, 0.15, 10)
	recOne := RecordFromEvidence(mk(1.0), now, 7*24*time.Hour, 15, 0.5, 0.15, 10)
	if recHigh.Score != recOne.Score {
		t.Errorf("EvidenceWeight=5.0 should clamp to 1.0: %v != %v", recHigh.Score, recOne.Score)
	}

	recNeg := RecordFromEvidence(mk(-3.0), now, 7*24*time.Hour, 15, 0.5, 0.15, 10)
	if recNeg.Score != 0 {
		t.Errorf("EvidenceWeight=-3.0 should clamp to 0 trust and yield score 0, got %v", recNeg.Score)
	}
}

// TestRecordFromEvidenceNaNWeightYieldsFiniteScore proves a NaN EvidenceWeight
// (which compares false to both < 0 and > 1, so it can slip past a naive
// clamp) is treated as 0 trust and never propagates into the returned Score.
// Wire-unreachable today (the JSON decoder rejects NaN literals), but a
// defense-in-depth guard for the planned gossip-side evidence import.
func TestRecordFromEvidenceNaNWeightYieldsFiniteScore(t *testing.T) {
	now := time.Now().UTC()
	ev := proto.EvidenceAggregate{
		IP:               "203.0.113.10",
		Scenarios:        []string{"ssh-probe"},
		WindowLast:       now,
		DiversityBuckets: map[string]int{"groups": 3},
		EvidenceWeight:   math.NaN(),
	}
	rec := RecordFromEvidence(ev, now, 7*24*time.Hour, 15, 0.5, 0.15, 10)

	if rec.Score != rec.Score { // NaN != NaN
		t.Fatalf("expected finite Score, got NaN")
	}
	if rec.Score < 0 || rec.Score > 100 {
		t.Errorf("Score out of [0,100] range: %v", rec.Score)
	}
	if len(rec.Groups) != 0 {
		t.Errorf("federated record must never carry Groups: %+v", rec.Groups)
	}
}

func TestRecordFromEvidenceSubnetCapsDiversity(t *testing.T) {
	now := time.Now().UTC()
	hl := 7 * 24 * time.Hour
	base := proto.EvidenceAggregate{
		IP: "203.0.113.7", Scenarios: []string{"ssh-auth-success"}, WindowLast: now, EvidenceWeight: 1.0,
	}
	// Many groups but ONE subnet → damped to roughly one diverse vote.
	oneSubnet := base
	oneSubnet.DiversityBuckets = map[string]int{"groups": 40, "subnets": 1}
	// Many groups across MANY subnets → full diversity.
	manySubnets := base
	manySubnets.DiversityBuckets = map[string]int{"groups": 40, "subnets": 40}

	low := RecordFromEvidence(oneSubnet, now, hl, 15, 0.5, 0.15, 10)
	high := RecordFromEvidence(manySubnets, now, hl, 15, 0.5, 0.15, 10)

	// Same group count (40), different subnet diversity: the broad answer must
	// score strictly higher (its votes are all full-weight; the one-subnet
	// answer's are mostly damped). Strict inequality is the robust property —
	// exact magnitudes depend on the logistic curve, so we don't pin them.
	if !(high.Score > low.Score) {
		t.Errorf("many subnets (%v) must outscore one subnet (%v)", high.Score, low.Score)
	}
	if low.Score <= 0 {
		t.Errorf("one-subnet answer should still recompute a positive score, got %v", low.Score)
	}
	// Invariant intact.
	if len(low.Groups) != 0 || low.Corroboration != 0 {
		t.Errorf("federated record leaked corroboration: %+v", low)
	}
}

func TestRecordFromEvidenceDisputesLowerScore(t *testing.T) {
	now := time.Now().UTC()
	hl := 7 * 24 * time.Hour
	base := proto.EvidenceAggregate{
		IP: "203.0.113.7", Scenarios: []string{"ssh-auth-success"}, WindowLast: now, EvidenceWeight: 1.0,
		DiversityBuckets: map[string]int{"groups": 10, "subnets": 10},
	}
	undisputed := RecordFromEvidence(base, now, hl, 15, 0.5, 0.15, 10)
	disputedEv := base
	disputedEv.DiversityBuckets = map[string]int{"groups": 10, "subnets": 10, "dispute_subnets": 8}
	disputed := RecordFromEvidence(disputedEv, now, hl, 15, 0.5, 0.15, 10)
	if !(disputed.Score < undisputed.Score) {
		t.Errorf("dispute_subnets must lower the recomputed score: %v !< %v", disputed.Score, undisputed.Score)
	}
	if len(disputed.Groups) != 0 { // Groups-empty invariant (E2) preserved
		t.Errorf("recompute must not leak Groups: %+v", disputed)
	}
}
