//go:build adversarial

package adversarial

import (
	"strconv"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

// TestGossipFloodShedsButNeverMisenforces: a stranger gossip flood pushes the
// victim into shed mode (SheddingForTest true) but pushes no block — shedding
// only ever reduces network participation, never enforcement (spec §11.5).
func TestGossipFloodShedsButNeverMisenforces(t *testing.T) {
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.Resources.MaxEventsPerSec = 5 // tiny budget so the flood trips shedding
	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.CloseStores()
	sink := &mockSink{}
	n.SetSinkForTest(sink)

	for i := 0; i < 200; i++ {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: "203.0.113." + strconv.Itoa(i%254+1), Reason: "ssh-auth-bruteforce", ReporterID: "flooder", SubnetID: "s", Timestamp: time.Now()},
			From:  "flooder",
		})
	}
	// The flood tripped shed mode...
	if !n.SheddingForTest() {
		t.Fatalf("a 200-event flood over a 5/s budget must trip shed mode")
	}
	// ...but shed mode never fabricates a block (strangers cannot block, and
	// shedding only drops network work — it never enforces).
	if len(sink.blocked) > 0 {
		t.Errorf("gossip flood must never push a block, got %v", sink.blocked)
	}
}
