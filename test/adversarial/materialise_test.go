//go:build adversarial

package adversarial

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/store"
)

// matNode builds a materialise-enabled node with a mock sink and optional
// never-block entries. neverBlock IPs go through cfg.Enforce.ExtraWhitelist,
// which n.neverblock.Contains checks (same precedence the gate uses).
func matNode(t *testing.T, neverBlock []string) (*node.Node, *mockSink) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationMaterialize = true // gate enabled
	cfg.Enforce.ExtraWhitelist = neverBlock
	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n.CloseStores() })
	sink := &mockSink{}
	n.SetSinkForTest(sink)
	return n, sink
}

func blockWorthy() store.ScoreRecord {
	return store.ScoreRecord{Score: 90, FirstSeen: time.Now().Add(-time.Hour), LastSeen: time.Now(), Reasons: []string{"ssh-auth-success"}}
}

func TestMaterialiseGateIsLoadBearing(t *testing.T) {
	// Positive control: diverse (4 subnets), high score, not whitelisted → 1 block.
	n, sink := matNode(t, nil)
	n.MaterialiseForTest("203.0.113.90", blockWorthy(), 4)
	if len(sink.blockedFor) != 1 || sink.blockedFor[0].IP != "203.0.113.90" {
		t.Fatalf("block-worthy diverse verdict must materialise; got %+v", sink.blockedFor)
	}

	// (a) Forged: many groups but only 1 subnet (< floor 3) → 0 blocks.
	n2, sink2 := matNode(t, nil)
	n2.MaterialiseForTest("203.0.113.91", blockWorthy(), 1)
	if len(sink2.blockedFor) != 0 {
		t.Errorf("single-subnet verdict must NOT materialise; got %+v", sink2.blockedFor)
	}

	// (b) Whitelisted (never-block) IP, otherwise block-worthy → 0 blocks.
	n3, sink3 := matNode(t, []string{"203.0.113.92"})
	n3.MaterialiseForTest("203.0.113.92", blockWorthy(), 4)
	if len(sink3.blockedFor) != 0 {
		t.Errorf("never-block IP must NOT materialise; got %+v", sink3.blockedFor)
	}

	// (c) Below-threshold score (< 80), diverse → 0 blocks.
	n4, sink4 := matNode(t, nil)
	low := blockWorthy()
	low.Score = 50
	n4.MaterialiseForTest("203.0.113.93", low, 4)
	if len(sink4.blockedFor) != 0 {
		t.Errorf("below-threshold verdict must NOT materialise; got %+v", sink4.blockedFor)
	}

	// (d) Disabled feature → 0 blocks even when block-worthy.
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationMaterialize = false
	n5, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n5.CloseStores() })
	sink5 := &mockSink{}
	n5.SetSinkForTest(sink5)
	n5.MaterialiseForTest("203.0.113.94", blockWorthy(), 4)
	if len(sink5.blockedFor) != 0 {
		t.Errorf("disabled materialise must be a no-op; got %+v", sink5.blockedFor)
	}
}
