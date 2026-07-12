package repquery

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// fakeStore returns a fixed record for one IP, empty otherwise.
type fakeStore struct {
	ip  string
	rec store.ScoreRecord
}

func (f fakeStore) GetScore(ip string) (store.ScoreRecord, error) {
	if ip == f.ip {
		return f.rec, nil
	}
	return store.ScoreRecord{}, nil
}

func TestResponderServesLocalEvidence(t *testing.T) {
	ctx := context.Background()
	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h1: %v", err)
	}
	defer h1.Close()
	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h2: %v", err)
	}
	defer h2.Close()

	rec := store.ScoreRecord{Score: 88, Corroboration: 2, ReporterIDs: []string{"peer1", "peer2"}, LastSeen: time.Now()}
	RegisterResponder(h1, fakeStore{ip: "1.2.3.4", rec: rec}, fakeAuth{anchored: true})

	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	s, err := h2.NewStream(ctx, h1.ID(), ProtocolID)
	if err != nil {
		t.Fatalf("newstream: %v", err)
	}
	defer s.Close()
	if err := json.NewEncoder(s).Encode(proto.RepQuery{IP: "1.2.3.4"}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var ev proto.EvidenceAggregate
	if err := json.NewDecoder(s).Decode(&ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.IP != "1.2.3.4" || ev.WindowLast.IsZero() {
		t.Errorf("responder answer = %+v, want IP 1.2.3.4 with non-zero WindowLast", ev)
	}
	if ev.DiversityBuckets["reporters"] != len(rec.ReporterIDs) {
		t.Errorf("DiversityBuckets[reporters] = %d, want %d", ev.DiversityBuckets["reporters"], len(rec.ReporterIDs))
	}
}

func TestResponderUnknownIPIsEmpty(t *testing.T) {
	ctx := context.Background()
	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h1: %v", err)
	}
	defer h1.Close()
	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h2: %v", err)
	}
	defer h2.Close()

	RegisterResponder(h1, fakeStore{ip: "1.2.3.4", rec: store.ScoreRecord{Score: 88, Corroboration: 2, LastSeen: time.Now()}}, fakeAuth{anchored: true})

	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	s, err := h2.NewStream(ctx, h1.ID(), ProtocolID)
	if err != nil {
		t.Fatalf("newstream: %v", err)
	}
	defer s.Close()
	if err := json.NewEncoder(s).Encode(proto.RepQuery{IP: "8.8.8.8"}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var ev proto.EvidenceAggregate
	if err := json.NewDecoder(s).Decode(&ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !ev.WindowLast.IsZero() {
		t.Errorf("unknown IP should return empty aggregate, got WindowLast=%v", ev.WindowLast)
	}
}

// TestResponderStreamDeadlineClosesIdleStream: a hostile peer that opens a
// stream and never writes a request must not pin the responder's handler
// goroutine forever (slowloris). The responder must hit its stream deadline
// and tear down the stream, which the client observes as a read error/EOF
// within a bounded wait.
func TestResponderStreamDeadlineClosesIdleStream(t *testing.T) {
	old := responderStreamTimeout
	responderStreamTimeout = 200 * time.Millisecond
	defer func() { responderStreamTimeout = old }()

	ctx := context.Background()
	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h1: %v", err)
	}
	defer h1.Close()
	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h2: %v", err)
	}
	defer h2.Close()

	RegisterResponder(h1, fakeStore{ip: "1.2.3.4", rec: store.ScoreRecord{Score: 88, Corroboration: 2, LastSeen: time.Now()}}, fakeAuth{anchored: true})

	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	s, err := h2.NewStream(ctx, h1.ID(), ProtocolID)
	if err != nil {
		t.Fatalf("newstream: %v", err)
	}
	defer s.Close()

	// Deliberately never write a request. The responder should still tear
	// down the stream once its deadline fires, rather than blocking forever.
	done := make(chan struct{})
	var n int
	var readErr error
	go func() {
		buf := make([]byte, 64)
		n, readErr = s.Read(buf)
		close(done)
	}()

	select {
	case <-done:
		if readErr == nil && n > 0 {
			t.Errorf("expected an error/EOF once the responder's deadline fired, got n=%d err=nil", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle stream was never closed by the responder (deadline not honored)")
	}
}

// fakeAuth is a test Authorizer: anchored/blocked are fixed answers.
type fakeAuth struct {
	anchored bool
	blocked  bool
}

func (f fakeAuth) Resolve(string) (float64, string, bool) { return 0.9, "test", f.anchored }
func (f fakeAuth) IsBlocked(string) bool                  { return f.blocked }

// queryOnce opens a stream to h1 from h2, sends a RepQuery for ip and returns
// the decode result of the answer.
func queryOnce(t *testing.T, ctx context.Context, h2 host.Host, id peer.ID, addrs []multiaddr.Multiaddr, ip string) (proto.EvidenceAggregate, error) {
	t.Helper()
	if err := h2.Connect(ctx, peer.AddrInfo{ID: id, Addrs: addrs}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	s, err := h2.NewStream(ctx, id, ProtocolID)
	if err != nil {
		t.Fatalf("newstream: %v", err)
	}
	defer s.Close()
	if err := json.NewEncoder(s).Encode(proto.RepQuery{IP: ip}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var ev proto.EvidenceAggregate
	err = json.NewDecoder(s).Decode(&ev)
	return ev, err
}

func TestResponderAuthorization(t *testing.T) {
	ctx := context.Background()
	rec := store.ScoreRecord{Score: 88, Corroboration: 2, ReporterIDs: []string{"peer1"}, LastSeen: time.Now()}

	cases := []struct {
		name    string
		auth    Authorizer
		wantErr bool
	}{
		{"anchored peer answered", fakeAuth{anchored: true}, false},
		{"stranger reset", fakeAuth{anchored: false}, true},
		{"blocked anchored peer reset", fakeAuth{anchored: true, blocked: true}, true},
		{"nil authorizer rejects all", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
			if err != nil {
				t.Fatalf("h1: %v", err)
			}
			defer h1.Close()
			h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
			if err != nil {
				t.Fatalf("h2: %v", err)
			}
			defer h2.Close()
			RegisterResponder(h1, fakeStore{ip: "1.2.3.4", rec: rec}, tc.auth)

			ev, err := queryOnce(t, ctx, h2, h1.ID(), h1.Addrs(), "1.2.3.4")
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected reset/decode error for unauthorized peer, got answer %+v", ev)
				}
				return
			}
			if err != nil {
				t.Fatalf("authorized query failed: %v", err)
			}
			if ev.WindowLast.IsZero() {
				t.Errorf("answer WindowLast is zero, want a real answer for a known IP")
			}
			if ev.DiversityBuckets["reporters"] < 1 {
				t.Errorf("answer DiversityBuckets[reporters] = %d, want >= 1", ev.DiversityBuckets["reporters"])
			}
		})
	}
}
