package transport_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/swarmguard/internal/transport"
)

// TestDHTFindPeerViaRelay proves a leaf can resolve another leaf's address
// through the relay's DHT routing table — no direct leaf-to-leaf connection needed.
func TestDHTFindPeerViaRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	relay, err := transport.New(ctx, testOpts(t, transport.ModeRelay))
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	defer relay.Close()

	leaf1, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create leaf1: %v", err)
	}
	defer leaf1.Close()

	leaf2, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create leaf2: %v", err)
	}
	defer leaf2.Close()

	// Both leaves bootstrap from relay; no direct leaf↔leaf connection.
	relayInfo := peer.AddrInfo{ID: relay.Host().ID(), Addrs: relay.Host().Addrs()}
	if err := leaf1.Bootstrap(ctx, []peer.AddrInfo{relayInfo}); err != nil {
		t.Fatalf("leaf1 bootstrap: %v", err)
	}
	if err := leaf2.Bootstrap(ctx, []peer.AddrInfo{relayInfo}); err != nil {
		t.Fatalf("leaf2 bootstrap: %v", err)
	}

	// Allow routing tables to populate.
	time.Sleep(500 * time.Millisecond)

	found, err := leaf1.FindPeer(ctx, leaf2.Host().ID())
	if err != nil {
		t.Fatalf("FindPeer: %v", err)
	}
	if found.ID != leaf2.Host().ID() {
		t.Fatalf("found wrong peer: got %s, want %s", found.ID, leaf2.Host().ID())
	}
}
