package repquery

import (
	"testing"
	"time"

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
	rec := RecordFromEvidence(ev, now, 7*24*time.Hour, 15, 0.5)

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
	recMore := RecordFromEvidence(evMore, now, 7*24*time.Hour, 15, 0.5)
	if recMore.Score <= rec.Score {
		t.Errorf("more groups should recompute higher: %v !> %v", recMore.Score, rec.Score)
	}
}

func TestRecordFromEvidenceNotFoundAndStrangerOnly(t *testing.T) {
	now := time.Now().UTC()
	// Zero WindowLast => empty record (not found).
	empty := RecordFromEvidence(proto.EvidenceAggregate{IP: "1.1.1.1"}, now, time.Hour, 15, 0.5)
	if !empty.LastSeen.IsZero() || empty.Score != 0 {
		t.Errorf("not-found evidence should yield empty record, got %+v", empty)
	}
	// Stranger-only evidence is bounded by the local stranger cap.
	strangerOnly := proto.EvidenceAggregate{
		IP: "2.2.2.2", Scenarios: []string{"smtp-spamtrap"}, WindowLast: now,
		DiversityBuckets: map[string]int{"groups": 0, "reporters": 5}, StrangersPresent: true, EvidenceWeight: 1.0,
	}
	rec := RecordFromEvidence(strangerOnly, now, 7*24*time.Hour, 15, 0.5)
	if rec.Score > 15.001 {
		t.Errorf("stranger-only evidence exceeded local cap: %v", rec.Score)
	}
	if len(rec.Groups) != 0 {
		t.Errorf("stranger-only must not add groups: %+v", rec.Groups)
	}
}
