package repquery

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/pkg/proto"

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
	RegisterResponder(agg, counter, fakeAuth{anchored: true})

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

// TestQuerierTimeoutDoesNotHang: an aggregator that accepts the stream and reads
// the request but never writes a response must not wedge Query — the stream
// deadline + deadline-aware fanout must return ok=false within a few×timeout.
// Without the fix this test hangs the go-test process (that is the failure).
func TestQuerierTimeoutDoesNotHang(t *testing.T) {
	ctx := context.Background()
	agg, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("agg: %v", err)
	}
	defer agg.Close()
	// Handler reads the request, then blocks until the stream is torn down.
	agg.SetStreamHandler(ProtocolID, func(s network.Stream) {
		defer s.Close()
		var q proto.RepQuery
		_ = json.NewDecoder(s).Decode(&q)
		<-ctx.Done() // never fires during the test; simulates a hung responder
	})

	client, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	q := NewQuerier(client, []peer.AddrInfo{{ID: agg.ID(), Addrs: agg.Addrs()}}, 200*time.Millisecond, time.Minute)

	done := make(chan struct{})
	var gotOK bool
	go func() {
		_, gotOK = q.Query(ctx, "9.9.9.9")
		close(done)
	}()
	select {
	case <-done:
		if gotOK {
			t.Errorf("hung aggregator should yield ok=false, got ok=true")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Query hung past the timeout (deadline not honored)")
	}
}

// TestQuerierPreservesScoreZeroAnswer: a known-but-clean record (Score 0,
// LastSeen set) must survive the max-score merge with ok=true and a non-zero
// LastSeen — not collapse into the "not found" (zero LastSeen) sentinel.
func TestQuerierPreservesScoreZeroAnswer(t *testing.T) {
	ctx := context.Background()
	agg, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("agg: %v", err)
	}
	defer agg.Close()
	RegisterResponder(agg, &countStore{ip: "7.7.7.7", rec: store.ScoreRecord{Score: 0, Corroboration: 2, LastSeen: time.Now()}}, fakeAuth{anchored: true})

	client, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	q := NewQuerier(client, []peer.AddrInfo{{ID: agg.ID(), Addrs: agg.Addrs()}}, 2*time.Second, time.Minute)
	e, ok := q.Query(ctx, "7.7.7.7")
	if !ok {
		t.Fatal("known-but-clean answer (score 0) should return ok=true")
	}
	if e.LastSeen.IsZero() {
		t.Errorf("score-0 answer lost its fields: LastSeen is zero, got %+v", e)
	}
	if e.Corroboration != 2 {
		t.Errorf("score-0 answer lost Corroboration: got %d want 2", e.Corroboration)
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
