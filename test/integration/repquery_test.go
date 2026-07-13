package integration_test

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/repquery"
	"github.com/JoeRu/federloom/internal/store"
)

// storeStub is a minimal repquery.Store for the integration test.
type storeStub struct{ m map[string]store.ScoreRecord }

func (s storeStub) GetScore(ip string) (store.ScoreRecord, error) { return s.m[ip], nil }

// allowAllAuth is a test repquery.Authorizer that authorizes every peer.
type allowAllAuth struct{}

func (allowAllAuth) Resolve(string) (float64, string, bool) { return 1, "test", true }
func (allowAllAuth) IsBlocked(string) bool                  { return false }

func TestFederatedLookupFetchesFromAggregator(t *testing.T) {
	// Aggregator B: has 203.0.113.9 scored, serves the responder.
	bHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("bHost: %v", err)
	}
	defer bHost.Close()
	repquery.RegisterResponder(bHost, storeStub{m: map[string]store.ScoreRecord{
		"203.0.113.9": {Score: 92, Corroboration: 4, Groups: []string{"p1", "p2"}, LastSeen: time.Now()},
	}}, allowAllAuth{})

	// Querier A: empty local store, B configured as aggregator.
	aHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("aHost: %v", err)
	}
	defer aHost.Close()
	q := repquery.NewQuerier(aHost, []peer.AddrInfo{{ID: bHost.ID(), Addrs: bHost.Addrs()}}, 2*time.Second, time.Minute, 7*24*time.Hour, 15, 0.5, 0.15)
	resolver := repquery.NewResolver(storeStub{m: map[string]store.ScoreRecord{}}, q, nil)

	// A resolves an IP it does not hold → fetched from B, recomputed under A's own parameters.
	rec, err := resolver.GetScore("203.0.113.9")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if rec.LastSeen.IsZero() || rec.Score <= 0 {
		t.Errorf("federated lookup = %+v, want a positive recomputed score with non-zero LastSeen", rec)
	}

	// An IP nobody has → empty.
	if rec, _ := resolver.GetScore("203.0.113.10"); !rec.LastSeen.IsZero() {
		t.Errorf("unknown IP should stay empty, got %+v", rec)
	}
}
