package integration_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

func newLocalAddr(t *testing.T) multiaddr.Multiaddr {
	t.Helper()
	m, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("addr: %v", err)
	}
	return m
}

func TestBridgeReemitsAcrossSubnets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Bridge transport: home subnet "a", bridges into "b".
	bridgeTr, err := transport.New(ctx, transport.Options{
		ListenAddrs:   []multiaddr.Multiaddr{newLocalAddr(t)},
		Subnet:        "a",
		BridgeSubnets: []string{"b"},
	})
	if err != nil {
		t.Fatalf("bridge transport: %v", err)
	}
	defer bridgeTr.Close()

	// Observer transport on subnet "b" (stands in for a node C in subnet b).
	obsB, err := transport.New(ctx, transport.Options{
		ListenAddrs: []multiaddr.Multiaddr{newLocalAddr(t)},
		Subnet:      "b",
	})
	if err != nil {
		t.Fatalf("observer transport: %v", err)
	}
	defer obsB.Close()

	// Connect them so the subnet-"b" gossipsub mesh forms.
	if err := obsB.Host().Connect(ctx, peer.AddrInfo{ID: bridgeTr.Host().ID(), Addrs: bridgeTr.Host().Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Bridge node.Node on the bridge transport.
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationSubnet = "a"
	cfg.FederationBridgeSubnets = []string{"b"}
	bridge, err := node.New(cfg, bridgeTr)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer bridge.CloseStores()

	// A stranger event that arrived on subnet "a" (origin A).
	re := transport.ReceivedEvent{
		Event: proto.Event{
			IP:          "198.51.100.77",
			Reason:      "ssh-probe",
			ReporterID:  "origA",
			Timestamp:   time.Now().UTC(),
			OriginTrace: []string{"origA"},
		},
		From:   "origA",
		Subnet: "a",
	}

	// The bridge scores it and re-emits onto subnet "b".
	bridge.ProcessRemote(re)

	select {
	case got := <-obsB.Subscribe():
		if got.Event.IP != re.Event.IP {
			t.Errorf("observer got IP %q, want %q", got.Event.IP, re.Event.IP)
		}
		if got.Subnet != "b" {
			t.Errorf("re-emit arrived on subnet %q, want b", got.Subnet)
		}
		want := []string{"origA", bridge.SelfID()}
		if len(got.Event.OriginTrace) != len(want) {
			t.Fatalf("OriginTrace = %v, want %v", got.Event.OriginTrace, want)
		}
		for i := range want {
			if got.Event.OriginTrace[i] != want[i] {
				t.Errorf("OriginTrace[%d] = %q, want %q", i, got.Event.OriginTrace[i], want[i])
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("observer on subnet b did not receive the bridged event within 3s")
	}
}

// TestMultiBridgeEchoScoredOnce: a node reachable via TWO bridges receives two
// copies of the same origin event (identical signed content, different
// OriginTrace last hop). The dedup cache must score it exactly once.
// E1 design §4: first-seen wins; ledger minor "echo-suppression only
// single-bridge tested" closed here.
func TestMultiBridgeEchoScoredOnce(t *testing.T) {
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationSubnet = "b"
	c, err := node.New(cfg, nil) // leaf in subnet b; ProcessRemote driven directly
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer c.CloseStores()

	// A signed origin event. The signature covers IP|Reason|Timestamp|ReporterID
	// — NOT OriginTrace — so both bridged copies carry the same valid signature.
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	origID, err := identity.PeerIDFromPrivKey(priv)
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}
	base := proto.Event{
		IP:         "198.51.100.88",
		Reason:     "ssh-probe",
		ReporterID: origID,
		Timestamp:  time.Now().UTC(),
	}
	if err := identity.SignEvent(&base, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	copy1 := base
	copy1.OriginTrace = []string{origID, "12D3KooWbridge1"}
	copy2 := base
	copy2.OriginTrace = []string{origID, "12D3KooWbridge2"}

	c.ProcessRemote(transport.ReceivedEvent{Event: copy1, From: "12D3KooWbridge1", Subnet: "b"})
	rec1, err := c.GetScore("198.51.100.88")
	if err != nil || rec1.LastSeen.IsZero() {
		t.Fatalf("first bridged copy was not scored: %+v err=%v", rec1, err)
	}
	if rec1.Score >= 15 { // config.Defaults() Trust.StrangerScoreCap
		t.Fatalf("precondition: first stranger contribution (%v) already at/near the stranger cap — a second scoring would be undetectable; adjust weights", rec1.Score)
	}

	c.ProcessRemote(transport.ReceivedEvent{Event: copy2, From: "12D3KooWbridge2", Subnet: "b"})
	rec2, _ := c.GetScore("198.51.100.88")
	if rec2.Score != rec1.Score || rec2.Corroboration != rec1.Corroboration {
		t.Errorf("second copy via other bridge changed the record: %+v -> %+v (dedup failed)", rec1, rec2)
	}
}
