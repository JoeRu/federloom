//go:build adversarial

package adversarial

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/store"
)

func matDisputeNode(t *testing.T) (*node.Node, *mockSink) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationMaterialize = true
	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n.CloseStores() })
	sink := &mockSink{}
	n.SetSinkForTest(sink)
	return n, sink
}

func TestSybilDisputeFloodCannotClearBlock(t *testing.T) {
	// Single-subnet flood: 50 disputes, all from "sybil" → below the subnet floor.
	n, sink := matDisputeNode(t)
	n.MaterialiseForTest("203.0.113.80", store.ScoreRecord{Score: 90, LastSeen: time.Now()}, 4)
	for i := 0; i < 50; i++ {
		n.DisputeForTest("203.0.113.80", "sybil") // same subnet every time
	}
	for _, ip := range sink.unblocked {
		if ip == "203.0.113.80" {
			t.Fatalf("single-subnet dispute flood must NOT unblock a materialised block")
		}
	}

	// Diverse disputes: distinct subnets ≥ floor → unblock.
	n2, sink2 := matDisputeNode(t)
	n2.MaterialiseForTest("203.0.113.81", store.ScoreRecord{Score: 90, LastSeen: time.Now()}, 4)
	floor := config.Defaults().DisputeUnblockMinSubnets // 3
	for i := 0; i < floor; i++ {
		n2.DisputeForTest("203.0.113.81", "sub"+string(rune('a'+i)))
	}
	found := false
	for _, ip := range sink2.unblocked {
		if ip == "203.0.113.81" {
			found = true
		}
	}
	if !found {
		t.Errorf("diverse anchored disputes should unblock; unblocked=%v", sink2.unblocked)
	}
}

// TestStrangerFakedSubnetsCannotUnblock proves the Sybil-fabricated-subnet fix:
// a SINGLE unanchored node can claim as many distinct (fabricated, unsigned)
// SubnetIDs as it likes — Event.SubnetID is attacker-controlled — but must
// never be able to drive DisputeSubnetsSeen past DisputeUnblockMinSubnets and
// clear a materialised federated block. Pre-fix, ApplyDispute appended
// obs.Subnet to DisputeSubnetsSeen for ANY first-from-subnet dispute
// (anchored or not), so this flood alone would unblock the IP; this test
// would fail against that code.
func TestStrangerFakedSubnetsCannotUnblock(t *testing.T) {
	n, sink := matDisputeNode(t)
	n.MaterialiseForTest("203.0.113.82", store.ScoreRecord{Score: 90, LastSeen: time.Now()}, 4)

	floor := config.Defaults().DisputeUnblockMinSubnets // 3
	for i := 0; i < floor+2; i++ {
		// A single stranger, fabricating a distinct SubnetID every vote.
		n.DisputeAsStrangerForTest("203.0.113.82", "faked-subnet-"+string(rune('a'+i)))
	}
	for _, ip := range sink.unblocked {
		if ip == "203.0.113.82" {
			t.Fatalf("a stranger flood with fabricated distinct SubnetIDs must NOT unblock a materialised block")
		}
	}
}
