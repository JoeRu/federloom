//go:build adversarial

package adversarial

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/repquery"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

type denyAllAuth struct{}

func (denyAllAuth) Resolve(string) (float64, string, bool) { return 0, "", false }
func (denyAllAuth) IsBlocked(string) bool                  { return false }

type sybilStore struct{ rec store.ScoreRecord }

func (s sybilStore) GetScore(string) (store.ScoreRecord, error) { return s.rec, nil }

// TestSybilStrangerQueriersGainNothing: a wave of stranger peers hammering the
// repquery responder is reset every time — no data served, no crash, and the
// served store is never mutated (read-only + fail-closed authorization).
func TestSybilStrangerQueriersGainNothing(t *testing.T) {
	ctx := context.Background()
	srv, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("srv: %v", err)
	}
	defer srv.Close()
	repquery.RegisterResponder(srv, sybilStore{rec: store.ScoreRecord{Score: 99, LastSeen: time.Now()}}, denyAllAuth{})

	attempted := 0
	for i := 0; i < 5; i++ {
		sybil, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		if err != nil {
			t.Fatalf("sybil %d: %v", i, err)
		}
		if err := sybil.Connect(ctx, peer.AddrInfo{ID: srv.ID(), Addrs: srv.Addrs()}); err != nil {
			t.Fatalf("sybil %d connect: %v", i, err)
		}
		s, err := sybil.NewStream(ctx, srv.ID(), repquery.ProtocolID)
		if err != nil {
			sybil.Close()
			continue // rejection at stream-open is a valid reject, but must not be ALL outcomes
		}
		attempted++
		_ = json.NewEncoder(s).Encode(proto.RepQuery{IP: "1.2.3.4"})
		var e proto.ScoreEntry
		if err := json.NewDecoder(s).Decode(&e); err == nil {
			t.Errorf("sybil %d received an answer: %+v (authorization bypassed)", i, e)
		}
		_ = s.Close()
		sybil.Close()
	}
	if attempted == 0 {
		t.Fatal("no sybil ever reached the query stage — responder missing entirely (wiring regression), not rejecting")
	}
}
