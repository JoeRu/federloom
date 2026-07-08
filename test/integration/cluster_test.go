package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

func localOpts(t *testing.T, mode transport.NodeMode) transport.Options {
	t.Helper()
	ma, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("build listen addr: %v", err)
	}
	return transport.Options{ListenAddrs: []multiaddr.Multiaddr{ma}, Mode: mode}
}

// startCluster creates a relay node R and n leaf nodes. Leaves connect only to R.
// Returns relay first, then leaves. Caller must call Close() on each.
func startCluster(t *testing.T, ctx context.Context, nLeaves int) (*transport.Node, []*transport.Node) {
	t.Helper()

	relay, err := transport.New(ctx, localOpts(t, transport.ModeRelay))
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}

	relayInfo := peer.AddrInfo{ID: relay.Host().ID(), Addrs: relay.Host().Addrs()}
	leaves := make([]*transport.Node, nLeaves)
	for i := range leaves {
		leaf, err := transport.New(ctx, localOpts(t, transport.ModeLeaf))
		if err != nil {
			t.Fatalf("create leaf%d: %v", i, err)
		}
		// Leaf connects to relay only — no direct leaf↔leaf connections.
		if err := leaf.Host().Connect(ctx, relayInfo); err != nil {
			t.Fatalf("leaf%d connect to relay: %v", i, err)
		}
		leaves[i] = leaf
	}

	time.Sleep(500 * time.Millisecond) // gossipsub mesh stabilisation
	return relay, leaves
}

// TestStarTopologyGossipForward proves events from L0 reach all other nodes via relay.
func TestStarTopologyGossipForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	relay, leaves := startCluster(t, ctx, 4)
	defer relay.Close()
	for _, l := range leaves {
		defer l.Close()
	}

	want := proto.Event{IP: "198.51.100.42", Reason: "smtp-auth-bruteforce", ReporterID: "forward-test"}
	if err := leaves[0].Publish(ctx, want, ""); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// L1, L2, L3, and relay must all receive the event.
	receivers := append([]*transport.Node{relay}, leaves[1:]...)
	for i, r := range receivers {
		select {
		case got := <-r.Subscribe():
			if got.Event.IP != want.IP {
				t.Errorf("receiver %d: got IP %q, want %q", i, got.Event.IP, want.IP)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("receiver %d did not receive event within 3s", i)
		}
	}
}

// TestStarTopologyGossipSymmetric proves the relay is symmetric: L2 publishing reaches L0, L1, L3.
func TestStarTopologyGossipSymmetric(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	relay, leaves := startCluster(t, ctx, 4)
	defer relay.Close()
	for _, l := range leaves {
		defer l.Close()
	}

	want := proto.Event{IP: "203.0.113.99", Reason: "dict-attack", ReporterID: "symmetric-test"}
	if err := leaves[2].Publish(ctx, want, ""); err != nil {
		t.Fatalf("publish: %v", err)
	}

	receivers := []*transport.Node{relay, leaves[0], leaves[1], leaves[3]}
	for i, r := range receivers {
		select {
		case got := <-r.Subscribe():
			if got.Event.IP != want.IP {
				t.Errorf("receiver %d: got IP %q, want %q", i, got.Event.IP, want.IP)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("receiver %d did not receive event within 3s", i)
		}
	}
}

// TestDHTDiscoveryViaRelay proves a leaf can find another leaf through relay's DHT.
func TestDHTDiscoveryViaRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	relay, err := transport.New(ctx, localOpts(t, transport.ModeRelay))
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	defer relay.Close()

	relayInfo := peer.AddrInfo{ID: relay.Host().ID(), Addrs: relay.Host().Addrs()}

	leaf1, err := transport.New(ctx, localOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("leaf1: %v", err)
	}
	defer leaf1.Close()

	leaf2, err := transport.New(ctx, localOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("leaf2: %v", err)
	}
	defer leaf2.Close()

	if err := leaf1.Bootstrap(ctx, []peer.AddrInfo{relayInfo}); err != nil {
		t.Fatalf("leaf1 bootstrap: %v", err)
	}
	if err := leaf2.Bootstrap(ctx, []peer.AddrInfo{relayInfo}); err != nil {
		t.Fatalf("leaf2 bootstrap: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	found, err := leaf1.FindPeer(ctx, leaf2.Host().ID())
	if err != nil {
		t.Fatalf("FindPeer: %v", err)
	}
	if found.ID != leaf2.Host().ID() {
		t.Fatalf("found wrong peer %s, want %s", found.ID, leaf2.Host().ID())
	}
}
