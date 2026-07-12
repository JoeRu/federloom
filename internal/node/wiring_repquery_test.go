package node

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/repquery"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/internal/trust"
	"github.com/JoeRu/federloom/pkg/proto"
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
		"203.0.113.9": {Score: 91, Corroboration: 3, Groups: []string{"p1", "p2", "p3"}, LastSeen: time.Now()},
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
	if apiRec.Score <= 0 || apiRec.LastSeen.IsZero() {
		t.Errorf("api surface: got %+v, want a positive recomputed Score with non-zero LastSeen (resolver not wired into api.Server)", apiRec)
	}

	// DNSBL surface.
	dnsblRec, err := n.dnsbl.LookupForTest("203.0.113.9")
	if err != nil {
		t.Fatalf("dnsbl.LookupForTest: %v", err)
	}
	if dnsblRec.Score <= 0 || dnsblRec.LastSeen.IsZero() {
		t.Errorf("dnsbl surface: got %+v, want a positive recomputed Score with non-zero LastSeen (resolver not wired into dnsbl.Server)", dnsblRec)
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

// TestResponderServeRoleAuthz: a federated node (transport, NO aggregators)
// registers the responder; an anchored client is answered, a stranger is reset.
func TestResponderServeRoleAuthz(t *testing.T) {
	ctx := context.Background()

	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	// NO cfg.FederationAggregators — pure serve role.

	// Anchor a person and vouch the client host's peer ID BEFORE node.New,
	// so the trust store loads both at construction.
	client, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()
	priv, err := identity.GeneratePersonKey(filepath.Join(t.TempDir(), "p.key"))
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), []trust.Anchor{{
		Person: "p", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "test",
	}}); err != nil {
		t.Fatalf("save anchors: %v", err)
	}
	cert := identity.IssueCert(priv, client.ID().String(), time.Now().Add(time.Hour))
	if err := trust.SaveCerts(cfg.TrustCertsFile(), []proto.PeerCert{cert}); err != nil {
		t.Fatalf("save certs: %v", err)
	}

	tr, err := transport.New(ctx, wiringLeafOpts(t))
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	defer tr.Close()

	n, err := New(cfg, tr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	// Seed a known record directly in the node's store so the anchored query
	// below exercises a real answer, not just "stream didn't error".
	if err := n.store.PutScore("203.0.113.50", store.ScoreRecord{
		Score: 77, Corroboration: 1, Groups: []string{"p1"}, LastSeen: time.Now(),
	}, time.Hour); err != nil {
		t.Fatalf("seed score: %v", err)
	}

	// Anchored client: stream completes, decodes a real EvidenceAggregate.
	if err := client.Connect(ctx, peer.AddrInfo{ID: tr.Host().ID(), Addrs: tr.Host().Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	s, err := client.NewStream(ctx, tr.Host().ID(), repquery.ProtocolID)
	if err != nil {
		t.Fatalf("anchored newstream: %v", err)
	}
	if err := json.NewEncoder(s).Encode(proto.RepQuery{IP: "203.0.113.50"}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var ev proto.EvidenceAggregate
	if err := json.NewDecoder(s).Decode(&ev); err != nil {
		t.Fatalf("anchored client should get an answer, got: %v", err)
	}
	if ev.WindowLast.IsZero() {
		t.Errorf("anchored client got an empty answer for a known IP: %+v", ev)
	}
	_ = s.Close()

	// Stranger: stream is reset before an answer.
	stranger, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("stranger: %v", err)
	}
	defer stranger.Close()
	if err := stranger.Connect(ctx, peer.AddrInfo{ID: tr.Host().ID(), Addrs: tr.Host().Addrs()}); err != nil {
		t.Fatalf("stranger connect: %v", err)
	}
	s2, err := stranger.NewStream(ctx, tr.Host().ID(), repquery.ProtocolID)
	if err != nil {
		t.Fatalf("stranger newstream: %v", err)
	}
	_ = json.NewEncoder(s2).Encode(proto.RepQuery{IP: "203.0.113.50"})
	var ev2 proto.EvidenceAggregate
	if err := json.NewDecoder(s2).Decode(&ev2); err == nil {
		t.Errorf("stranger should be reset, got answer %+v", ev2)
	}
	_ = s2.Close()
}
