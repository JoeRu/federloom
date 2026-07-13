package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/repquery"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

// recSink records BlockFor calls (ip, ttl).
type recSink struct {
	blockedFor []struct {
		IP  string
		TTL time.Duration
	}
}

func (r *recSink) Name() string                { return "rec" }
func (r *recSink) Start(context.Context) error { return nil }
func (r *recSink) Block(string) error          { return nil }
func (r *recSink) BlockFor(ip string, ttl time.Duration) error {
	r.blockedFor = append(r.blockedFor, struct {
		IP  string
		TTL time.Duration
	}{ip, ttl})
	return nil
}
func (r *recSink) Unblock(string) error { return nil }
func (r *recSink) Close() error         { return nil }

// aggMultiaddr returns a dialable multiaddr (including /p2p/<id>) for host,
// suitable for cfg.FederationAggregators.
func aggMultiaddr(t *testing.T, host interface {
	Addrs() []multiaddr.Multiaddr
	ID() peer.ID
}) string {
	t.Helper()
	if len(host.Addrs()) == 0 {
		t.Fatal("aggMultiaddr: host has no listen addrs")
	}
	return host.Addrs()[0].String() + "/p2p/" + host.ID().String()
}

// newMatTransport builds a loopback transport.Node for the materialise test.
func newMatTransport(t *testing.T, ctx context.Context) *transport.Node {
	t.Helper()
	tr, err := transport.New(ctx, transport.Options{
		ListenAddrs: []multiaddr.Multiaddr{newLocalAddr(t)},
	})
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr
}

func TestMaterialiseFederatedVerdict(t *testing.T) {
	ctx := context.Background()

	// Aggregator B: a diverse, block-worthy IP (high groups + many subnets).
	bHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("bHost: %v", err)
	}
	defer bHost.Close()
	// NOTE: the resolver recomputes the score under the CONSUMER's own
	// parameters (spec §8) from DiversityBuckets["groups"/"subnets"], not the
	// raw Score field below — so Groups/SubnetsSeen must be wide enough that
	// the recomputed score actually clears FederationBlockThreshold (80,
	// default). 10 distinct full-weight synthetic votes at weight
	// 0.5*40 comfortably exceed it (~89).
	blockworthy := store.ScoreRecord{
		Score: 90, LastSeen: time.Now(),
		Reasons: []string{"ssh-auth-success"},
		Groups:  []string{"g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8", "g9", "g10"},
		SubnetsSeen: []string{
			"s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10",
		}, // 10 subnets >= floor 3
	}
	lowDiversity := store.ScoreRecord{
		Score: 90, LastSeen: time.Now(),
		Reasons:     []string{"ssh-auth-success"},
		Groups:      []string{"g1"},
		SubnetsSeen: []string{"s1"}, // below floor 3
	}
	repquery.RegisterResponder(bHost, storeStub{m: map[string]store.ScoreRecord{
		"203.0.113.90": blockworthy,
		"203.0.113.91": lowDiversity,
		"203.0.113.93": blockworthy, // block-worthy, but whitelisted locally on A
	}}, allowAllAuth{})

	// Node A: materialise enabled, B configured as aggregator, mock sink.
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationMaterialize = true
	cfg.FederationAggregators = []string{aggMultiaddr(t, bHost)}
	cfg.FederationQueryTimeout = config.Duration{Duration: 5 * time.Second}

	// Pre-seed A's local-only whitelist so the never-block/whitelist gate has
	// something to catch, before the node (and its WhitelistStore) is built.
	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	if err := wl.Add(proto.WhitelistEntry{IPOrRange: "203.0.113.93"}); err != nil {
		t.Fatalf("whitelist add: %v", err)
	}

	trA := newMatTransport(t, ctx)
	n, err := node.New(cfg, trA)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.CloseStores()
	sink := &recSink{}
	n.SetSinkForTest(sink)

	// Drive A's federated read path for the IP (point lookup routes through the resolver).
	if _, err := n.ScoreViaPointReaderForTest("203.0.113.90"); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(sink.blockedFor) != 1 || sink.blockedFor[0].IP != "203.0.113.90" {
		t.Fatalf("expected a materialised block for 203.0.113.90, got %+v", sink.blockedFor)
	}
	if sink.blockedFor[0].TTL != cfg.EffectiveFederationBlockTTL() {
		t.Errorf("materialised TTL = %v, want %v", sink.blockedFor[0].TTL, cfg.EffectiveFederationBlockTTL())
	}

	// A low-diversity verdict must NOT be materialised.
	if _, err := n.ScoreViaPointReaderForTest("203.0.113.91"); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(sink.blockedFor) != 1 {
		t.Fatalf("low-diversity IP should not be materialised, got %+v", sink.blockedFor)
	}

	// A whitelisted IP must NOT be materialised even though it is block-worthy
	// (never-block/whitelist always wins over the diversity gate).
	if _, err := n.ScoreViaPointReaderForTest("203.0.113.93"); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(sink.blockedFor) != 1 {
		t.Fatalf("whitelisted IP should not be materialised, got %+v", sink.blockedFor)
	}

	// Direct gate seam (Task 5 helper): a fabricated block-worthy verdict for a
	// non-whitelisted IP must materialise, confirming MaterialiseForTest drives
	// the same gate.
	n.MaterialiseForTest("203.0.113.94", blockworthy, 4)
	if len(sink.blockedFor) != 2 || sink.blockedFor[1].IP != "203.0.113.94" {
		t.Fatalf("expected MaterialiseForTest to materialise 203.0.113.94, got %+v", sink.blockedFor)
	}
}

// matNode builds a materialise-configured node (no transport needed — cases
// drive the gate directly via MaterialiseForTest) with a recording sink.
func matNode(t *testing.T, enabled bool) (*node.Node, *recSink) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationMaterialize = enabled
	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n.CloseStores() })
	sink := &recSink{}
	n.SetSinkForTest(sink)
	return n, sink
}

// TestMaterialiseGateIsANDNotOR isolates each half of the score∧subnets gate:
// a high-score/low-subnet verdict and a low-score/high-subnet verdict must both
// be refused. The main test's low-diversity fixture fails BOTH halves at once,
// so it cannot catch an accidental || → && (OR-gate) regression; these do.
func TestMaterialiseGateIsANDNotOR(t *testing.T) {
	// High score (90 ≥ 80), low subnets (1 < 3) → must NOT materialise.
	n1, s1 := matNode(t, true)
	n1.MaterialiseForTest("203.0.113.100", store.ScoreRecord{Score: 90, LastSeen: time.Now()}, 1)
	if len(s1.blockedFor) != 0 {
		t.Errorf("high-score/low-subnet must not materialise (subnet floor); got %+v", s1.blockedFor)
	}

	// Low score (40 < 80), high subnets (8 ≥ 3) → must NOT materialise.
	n2, s2 := matNode(t, true)
	n2.MaterialiseForTest("203.0.113.101", store.ScoreRecord{Score: 40, LastSeen: time.Now()}, 8)
	if len(s2.blockedFor) != 0 {
		t.Errorf("low-score/high-subnet must not materialise (score threshold); got %+v", s2.blockedFor)
	}
}

// TestMaterialiseOptInOff proves the opt-in invariant: with
// federation_materialize disabled, an otherwise block-worthy verdict produces
// zero firewall writes (behaviour is byte-for-byte the read-only path).
func TestMaterialiseOptInOff(t *testing.T) {
	n, sink := matNode(t, false) // disabled
	n.MaterialiseForTest("203.0.113.95", store.ScoreRecord{Score: 99, LastSeen: time.Now()}, 10)
	if len(sink.blockedFor) != 0 {
		t.Errorf("disabled materialise must be a no-op; got %+v", sink.blockedFor)
	}
}
