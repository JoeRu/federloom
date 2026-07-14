package repquery

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/store"
)

func TestAggregateFromRecord(t *testing.T) {
	now := time.Now().UTC()
	r := store.ScoreRecord{
		Score:        60,
		FirstSeen:    now.Add(-time.Hour),
		LastSeen:     now,
		Reasons:      []string{"ssh-probe", "ssh-auth-bruteforce"},
		Groups:       []string{"jo", "al"},
		ReporterIDs:  []string{"p1", "p2", "p3"},
		StrangerSeen: true,
	}
	ev := AggregateFromRecord("203.0.113.7", r)
	if ev.IP != "203.0.113.7" || ev.DiversityBuckets["groups"] != 2 ||
		ev.DiversityBuckets["reporters"] != 3 || !ev.StrangersPresent ||
		!ev.WindowLast.Equal(now) || ev.EvidenceWeight != 1.0 || len(ev.Scenarios) != 2 {
		t.Errorf("projection wrong: %+v", ev)
	}
	// Privacy: no reporter identity leaks — only counts.
	// (Structural: EvidenceAggregate has no identity field; asserting the type
	// carries counts is enough.)

	// Empty record → not-found sentinel (zero WindowLast).
	empty := AggregateFromRecord("1.1.1.1", store.ScoreRecord{})
	if !empty.WindowLast.IsZero() {
		t.Errorf("empty record should yield zero WindowLast, got %v", empty.WindowLast)
	}
}

func TestAggregateShipsSubnetsBucket(t *testing.T) {
	r := store.ScoreRecord{
		LastSeen:    time.Now(),
		Groups:      []string{"jo", "al"},
		ReporterIDs: []string{"p1", "p2", "p3"},
		SubnetsSeen: []string{"a", "b", "c"},
	}
	ev := AggregateFromRecord("203.0.113.7", r)
	if ev.DiversityBuckets["subnets"] != 3 {
		t.Errorf("subnets bucket = %d, want 3", ev.DiversityBuckets["subnets"])
	}
	// Names never leave the node — only the count.
	// (Structural: EvidenceAggregate has no subnet-names field.)
}

func TestAggregateShipsDisputeSubnets(t *testing.T) {
	r := store.ScoreRecord{LastSeen: time.Now(), DisputeSubnetsSeen: []string{"a", "b"}}
	ev := AggregateFromRecord("203.0.113.7", r)
	if ev.DiversityBuckets["dispute_subnets"] != 2 {
		t.Errorf("dispute_subnets bucket = %d, want 2", ev.DiversityBuckets["dispute_subnets"])
	}
}
