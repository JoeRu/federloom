package repquery

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

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

func TestResponderServesLocalScore(t *testing.T) {
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

	RegisterResponder(h1, fakeStore{ip: "1.2.3.4", rec: store.ScoreRecord{Score: 88, Corroboration: 2, LastSeen: time.Now()}})

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
	var e proto.ScoreEntry
	if err := json.NewDecoder(s).Decode(&e); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e.IP != "1.2.3.4" || e.Score != 88 {
		t.Errorf("responder answer = %+v, want IP 1.2.3.4 score 88", e)
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

	RegisterResponder(h1, fakeStore{ip: "1.2.3.4", rec: store.ScoreRecord{Score: 88, Corroboration: 2, LastSeen: time.Now()}})

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
	var e proto.ScoreEntry
	if err := json.NewDecoder(s).Decode(&e); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !e.LastSeen.IsZero() {
		t.Errorf("unknown IP should return empty entry, got LastSeen=%v", e.LastSeen)
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

	RegisterResponder(h1, fakeStore{ip: "1.2.3.4", rec: store.ScoreRecord{Score: 88, Corroboration: 2, LastSeen: time.Now()}})

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
