package repquery

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/store"
)

func TestQuerierFetchesAndCaches(t *testing.T) {
	ctx := context.Background()
	// Aggregator host with a responder holding IP X.
	agg, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("agg: %v", err)
	}
	defer agg.Close()
	counter := &countStore{ip: "9.9.9.9", rec: store.ScoreRecord{Score: 70, Corroboration: 1, LastSeen: time.Now()}}
	RegisterResponder(agg, counter)

	client, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	q := NewQuerier(client, []peer.AddrInfo{{ID: agg.ID(), Addrs: agg.Addrs()}}, 2*time.Second, time.Minute)

	e, ok := q.Query(ctx, "9.9.9.9")
	if !ok || e.Score != 70 {
		t.Fatalf("Query = %+v ok=%v, want score 70 ok true", e, ok)
	}
	// Second query within TTL must hit the cache (no new responder call).
	before := counter.calls
	if _, ok := q.Query(ctx, "9.9.9.9"); !ok {
		t.Fatal("cached query lost the answer")
	}
	if counter.calls != before {
		t.Errorf("cache miss: responder called again (%d -> %d)", before, counter.calls)
	}

	// Unknown IP: no aggregator has it → ok false.
	if _, ok := q.Query(ctx, "8.8.8.8"); ok {
		t.Error("unknown IP should return ok=false")
	}
}

type countStore struct {
	ip    string
	rec   store.ScoreRecord
	calls int
}

func (c *countStore) GetScore(ip string) (store.ScoreRecord, error) {
	c.calls++
	if ip == c.ip {
		return c.rec, nil
	}
	return store.ScoreRecord{}, nil
}
