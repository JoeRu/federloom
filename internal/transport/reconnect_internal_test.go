package transport

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func newLocalNode(t *testing.T, ctx context.Context) *Node {
	t.Helper()
	n, err := New(ctx, Options{ListenAddrs: []multiaddr.Multiaddr{multiaddr.StringCast("/ip4/127.0.0.1/tcp/0")}, Mode: ModeLeaf})
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

// TestKeepBootstrapPeersProtectsInboundConnection: a configured bootstrap peer
// that is connected through some other path (here: it dialled us) must still
// be protected from connection trimming.
func TestKeepBootstrapPeersProtectsInboundConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leaf := newLocalNode(t, ctx)
	hub := newLocalNode(t, ctx)

	// The hub dials the leaf; the leaf never dials the hub itself.
	if err := hub.host.Connect(ctx, peer.AddrInfo{ID: leaf.host.ID(), Addrs: leaf.host.Addrs()}); err != nil {
		t.Fatalf("hub connect: %v", err)
	}
	hubInfo := peer.AddrInfo{ID: hub.host.ID(), Addrs: hub.host.Addrs()}
	go leaf.KeepBootstrapPeers(ctx, []peer.AddrInfo{hubInfo}, 50*time.Millisecond)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if leaf.host.ConnManager().IsProtected(hubInfo.ID, bootstrapProtectTag) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("bootstrap peer connected via an inbound connection was not protected")
}
