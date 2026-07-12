package repquery

import (
	"encoding/json"
	"log"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"

	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// ProtocolID is the libp2p stream protocol for on-demand reputation queries.
const ProtocolID = "/federloom/repquery/v2"

// responderStreamTimeout bounds a single query exchange (read request +
// write answer). A peer that opens a stream and stalls cannot pin the
// handler goroutine past this. Generous enough for a legitimate slow peer;
// a package var so tests can shorten it.
var responderStreamTimeout = 10 * time.Second

// Store is the minimal reader the responder needs (the local BadgerStore satisfies it).
type Store interface {
	GetScore(ip string) (store.ScoreRecord, error)
}

// Authorizer decides which peers may query this node's reputation
// (design 2026-07-10 §3: anchored AND not blocked; nil = reject all).
// *trust.Store satisfies it verbatim.
type Authorizer interface {
	Resolve(peerID string) (weight float64, group string, anchored bool)
	IsBlocked(peerID string) bool
}

// RegisterResponder installs the stream handler on h. Each stream is one
// RepQuery → one EvidenceAggregate, then closed. Read-only. Only peers authorized
// by auth are answered; unauthorized streams are reset before the request
// is read (fail closed: a nil auth rejects everyone).
func RegisterResponder(h host.Host, s Store, auth Authorizer) {
	h.SetStreamHandler(ProtocolID, func(str network.Stream) {
		peerID := str.Conn().RemotePeer().String()
		if auth == nil {
			log.Printf("repquery: reject %s: no authorizer configured", peerID)
			_ = str.Reset()
			return
		}
		if auth.IsBlocked(peerID) {
			log.Printf("repquery: reject blocked peer %s", peerID)
			_ = str.Reset()
			return
		}
		if _, _, anchored := auth.Resolve(peerID); !anchored {
			log.Printf("repquery: reject unanchored peer %s", peerID)
			_ = str.Reset()
			return
		}
		defer str.Close()
		if err := str.SetDeadline(time.Now().Add(responderStreamTimeout)); err != nil {
			log.Printf("repquery: set deadline for %s: %v", peerID, err)
		}
		var q proto.RepQuery
		if err := json.NewDecoder(str).Decode(&q); err != nil {
			log.Printf("repquery: bad request from %s: %v", peerID, err)
			_ = str.Reset()
			return
		}
		rec, err := s.GetScore(q.IP)
		if err != nil {
			log.Printf("repquery: store error for %s: %v", q.IP, err)
			return
		}
		// Empty record → EvidenceAggregate with zero WindowLast means "not found".
		if err := json.NewEncoder(str).Encode(AggregateFromRecord(q.IP, rec)); err != nil {
			log.Printf("repquery: write answer for %s: %v", peerID, err)
		}
	})
}
