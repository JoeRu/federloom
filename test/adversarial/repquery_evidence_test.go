//go:build adversarial

package adversarial

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/repquery"
	"github.com/JoeRu/federloom/pkg/proto"
)

// TestInflatedBucketsCannotForceBlock: a hostile aggregator claiming absurd
// diversity cannot (a) manufacture anchored corroboration (Groups stays empty,
// so the block backstop is never satisfied) nor (b) drive the recomputed score
// above the logistic ceiling. Containment for a lying aggregator is defederation.
func TestInflatedBucketsCannotForceBlock(t *testing.T) {
	now := time.Now().UTC()
	ev := proto.EvidenceAggregate{
		IP:               "203.0.113.99",
		Scenarios:        []string{"ssh-auth-success"}, // highest local weight (40)
		WindowLast:       now,
		DiversityBuckets: map[string]int{"groups": 500, "reporters": 5000},
		StrangersPresent: true,
		EvidenceWeight:   1.0,
	}
	rec := repquery.RecordFromEvidence(ev, now, 7*24*time.Hour, 15, 0.5)

	if len(rec.Groups) != 0 || rec.Corroboration != 0 {
		t.Fatalf("federated evidence manufactured corroboration: Groups=%v Corr=%d", rec.Groups, rec.Corroboration)
	}
	if rec.Score > 100 {
		t.Errorf("recomputed score exceeded logistic ceiling: %v", rec.Score)
	}
	// A record with no Groups can never satisfy the anchored-corroboration block
	// backstop (batch A: block requires len(Groups) > 0), regardless of score.
}
