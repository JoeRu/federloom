package transport_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/transport"
)

// freePort returns a TCP port that was free a moment ago, so a node can be
// restarted on the same address with the same identity.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func fixedNode(t *testing.T, ctx context.Context, key crypto.PrivKey, port int) *transport.Node {
	t.Helper()
	ma := multiaddr.StringCast(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port))
	n, err := transport.New(ctx, transport.Options{ListenAddrs: []multiaddr.Multiaddr{ma}, Mode: transport.ModeRelay, PrivKey: key})
	if err != nil {
		t.Fatalf("create fixed node: %v", err)
	}
	return n
}

func waitConnected(t *testing.T, n *transport.Node, id peer.ID, want bool, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if (n.Host().Network().Connectedness(id) == network.Connected) == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("connected to %s = %v after %s, want %v", id, !want, within, want)
}

// TestKeepBootstrapPeersReconnectsAfterHubRestart: a leaf whose only peer is
// its bootstrap hub must find its way back when the hub restarts. Without a
// reconnect loop the leaf stays isolated until it is restarted itself, because
// its DHT routing table emptied with the lost connection.
func TestKeepBootstrapPeersReconnectsAfterHubRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	hubKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	port := freePort(t)
	hub := fixedNode(t, ctx, hubKey, port)
	hubInfo := peer.AddrInfo{ID: hub.Host().ID(), Addrs: hub.Host().Addrs()}

	leaf, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	defer leaf.Close()

	if err := leaf.Bootstrap(ctx, []peer.AddrInfo{hubInfo}); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	go leaf.KeepBootstrapPeers(ctx, []peer.AddrInfo{hubInfo}, 100*time.Millisecond)

	hub.Close()
	waitConnected(t, leaf, hubInfo.ID, false, 5*time.Second)

	restarted := fixedNode(t, ctx, hubKey, port)
	defer restarted.Close()
	waitConnected(t, leaf, hubInfo.ID, true, 5*time.Second)

	// Reconnecting is not the goal in itself: discovery through the hub must
	// work again. A peer that only joins after the restart can be known to the
	// leaf solely through a DHT lookup via the restarted hub.
	other, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create other: %v", err)
	}
	defer other.Close()
	if err := other.Bootstrap(ctx, []peer.AddrInfo{hubInfo}); err != nil {
		t.Fatalf("other bootstrap: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		fctx, fcancel := context.WithTimeout(ctx, time.Second)
		ai, err := leaf.FindPeer(fctx, other.Host().ID())
		fcancel()
		if err == nil && len(ai.Addrs) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("leaf could not find a new peer via the restarted hub's DHT: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestBootstrapTriesEveryPeer: one unreachable bootstrap peer must not stop
// the node from connecting to the others listed after it.
func TestBootstrapTriesEveryPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	good, err := transport.New(ctx, testOpts(t, transport.ModeRelay))
	if err != nil {
		t.Fatalf("create good: %v", err)
	}
	defer good.Close()
	deadKey, _, _ := crypto.GenerateEd25519Key(rand.Reader)
	deadID, _ := peer.IDFromPrivateKey(deadKey)
	dead := peer.AddrInfo{ID: deadID, Addrs: []multiaddr.Multiaddr{
		multiaddr.StringCast(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", freePort(t)))}}

	leaf, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	defer leaf.Close()

	err = leaf.Bootstrap(ctx, []peer.AddrInfo{dead, {ID: good.Host().ID(), Addrs: good.Host().Addrs()}})
	if err == nil || !strings.Contains(err.Error(), deadID.String()) {
		t.Errorf("Bootstrap error = %v, want one naming the unreachable peer", err)
	}
	waitConnected(t, leaf, good.Host().ID(), true, 2*time.Second)
}
