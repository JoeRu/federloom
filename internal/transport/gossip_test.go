package transport_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

// testOpts returns options for a test node listening on a random localhost port.
func testOpts(t *testing.T, mode transport.NodeMode) transport.Options {
	t.Helper()
	ma, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("build listen addr: %v", err)
	}
	return transport.Options{
		ListenAddrs: []multiaddr.Multiaddr{ma},
		Mode:        mode,
	}
}

// connect wires two nodes together (caller → target).
func connect(t *testing.T, caller, target *transport.Node) {
	t.Helper()
	ai := peer.AddrInfo{ID: target.Host().ID(), Addrs: target.Host().Addrs()}
	if err := caller.Host().Connect(context.Background(), ai); err != nil {
		t.Fatalf("connect: %v", err)
	}
}

func TestTwoNodeGossip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeA, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create nodeA: %v", err)
	}
	defer nodeA.Close()

	nodeB, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create nodeB: %v", err)
	}
	defer nodeB.Close()

	connect(t, nodeA, nodeB)
	time.Sleep(500 * time.Millisecond) // allow gossipsub to graft

	want := proto.Event{IP: "192.0.2.1", Reason: "test-bruteforce", ReporterID: "tester"}
	if err := nodeA.Publish(ctx, want, ""); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case got := <-nodeB.Subscribe():
		if got.Event.IP != want.IP || got.Event.Reason != want.Reason {
			t.Fatalf("got %+v, want %+v", got.Event, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nodeB did not receive event within 3s")
	}
}

// TestSubscribeSurfacesVerifiedPublisher proves the receiver learns the
// gossipsub-verified origin peer ID, which the node layer compares against
// Event.ReporterID to kill spoofing.
func TestSubscribeSurfacesVerifiedPublisher(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeA, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create nodeA: %v", err)
	}
	defer nodeA.Close()
	nodeB, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create nodeB: %v", err)
	}
	defer nodeB.Close()

	connect(t, nodeA, nodeB)
	time.Sleep(500 * time.Millisecond)

	if err := nodeA.Publish(ctx, proto.Event{IP: "192.0.2.9", Reason: "test"}, ""); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case got := <-nodeB.Subscribe():
		if got.From != nodeA.Host().ID().String() {
			t.Errorf("From = %q, want publisher %q", got.From, nodeA.Host().ID())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event within 3s")
	}
}
