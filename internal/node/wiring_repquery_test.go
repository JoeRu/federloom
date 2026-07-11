package node

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/repquery"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/internal/transport"
)

// wiringStoreStub is a minimal repquery.Store for the aggregator side of the
// wiring test: only 203.0.113.9 is scored, everything else is empty (miss).
type wiringStoreStub struct{ m map[string]store.ScoreRecord }

func (s wiringStoreStub) GetScore(ip string) (store.ScoreRecord, error) { return s.m[ip], nil }

// allowAllAuth is a test repquery.Authorizer that authorizes every peer.
type allowAllAuth struct{}

func (allowAllAuth) Resolve(string) (float64, string, bool) { return 1, "test", true }
func (allowAllAuth) IsBlocked(string) bool                  { return false }

// wiringLeafOpts builds transport.Options for a loopback leaf node.
func wiringLeafOpts(t *testing.T) transport.Options {
	t.Helper()
	ma, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("build listen addr: %v", err)
	}
	return transport.Options{ListenAddrs: []multiaddr.Multiaddr{ma}, Mode: transport.ModeLeaf}
}

// TestNodeWiringFederatesBothReadSurfaces is the end-to-end regression guard
// for the node.New() federation wiring block: with federation ENABLED, it
// proves the resolver was injected into BOTH read surfaces (the score API's
// point reader and the DNSBL's store reader) by driving a real libp2p query
// against a stub aggregator. A control node with federation OFF proves the
// disabled path stays local-only.
//
// This is the regression test for the class of bug FederLoom hit in "E1":
// a wiring guard that silently dropped events with no test catching it.
func TestNodeWiringFederatesBothReadSurfaces(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// --- Aggregator B: plain libp2p host serving one known IP. ---
	bHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("bHost: %v", err)
	}
	defer bHost.Close()
	repquery.RegisterResponder(bHost, wiringStoreStub{m: map[string]store.ScoreRecord{
		"203.0.113.9": {Score: 91, Corroboration: 3, LastSeen: time.Now()},
	}}, allowAllAuth{})

	if len(bHost.Addrs()) == 0 {
		t.Fatalf("bHost has no listen addrs")
	}
	aggAddr := fmt.Sprintf("%s/p2p/%s", bHost.Addrs()[0], bHost.ID())

	// --- Node A: federation ENABLED, pointed at B. ---
	transportA, err := transport.New(ctx, wiringLeafOpts(t))
	if err != nil {
		t.Fatalf("transportA: %v", err)
	}
	defer transportA.Close()

	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationAggregators = []string{aggAddr}

	n, err := New(cfg, transportA)
	if err != nil {
		t.Fatalf("New (federation enabled): %v", err)
	}
	defer n.CloseStores()

	// Score API surface.
	apiRec, err := n.api.PointLookupForTest("203.0.113.9")
	if err != nil {
		t.Fatalf("api.PointLookupForTest: %v", err)
	}
	if apiRec.Score != 91 || apiRec.LastSeen.IsZero() {
		t.Errorf("api surface: got %+v, want Score 91 with non-zero LastSeen (resolver not wired into api.Server)", apiRec)
	}

	// DNSBL surface.
	dnsblRec, err := n.dnsbl.LookupForTest("203.0.113.9")
	if err != nil {
		t.Fatalf("dnsbl.LookupForTest: %v", err)
	}
	if dnsblRec.Score != 91 {
		t.Errorf("dnsbl surface: got %+v, want Score 91 (resolver not wired into dnsbl.Server)", dnsblRec)
	}

	// --- Control node A2: federation OFF, must stay local-only. ---
	transportA2, err := transport.New(ctx, wiringLeafOpts(t))
	if err != nil {
		t.Fatalf("transportA2: %v", err)
	}
	defer transportA2.Close()

	cfg2 := config.Defaults()
	cfg2.Store.Dir = t.TempDir()
	cfg2.FederationAggregators = nil

	n2, err := New(cfg2, transportA2)
	if err != nil {
		t.Fatalf("New (federation disabled): %v", err)
	}
	defer n2.CloseStores()

	ctrlRec, err := n2.api.PointLookupForTest("203.0.113.9")
	if err != nil {
		t.Fatalf("control api.PointLookupForTest: %v", err)
	}
	if !ctrlRec.LastSeen.IsZero() {
		t.Errorf("control node with federation disabled must not resolve remote IP, got %+v", ctrlRec)
	}
}
