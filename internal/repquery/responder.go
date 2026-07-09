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
const ProtocolID = "/federloom/repquery/v1"

// responderStreamTimeout bounds a single query exchange (read request +
// write answer). A peer that opens a stream and stalls cannot pin the
// handler goroutine past this. Generous enough for a legitimate slow peer;
// a package var so tests can shorten it.
var responderStreamTimeout = 10 * time.Second

// Store is the minimal reader the responder needs (the local BadgerStore satisfies it).
type Store interface {
	GetScore(ip string) (store.ScoreRecord, error)
}

// RegisterResponder installs the stream handler on h. Each stream is one
// RepQuery → one ScoreEntry, then closed. Read-only.
func RegisterResponder(h host.Host, s Store) {
	h.SetStreamHandler(ProtocolID, func(str network.Stream) {
		defer str.Close()
		_ = str.SetDeadline(time.Now().Add(responderStreamTimeout))
		var q proto.RepQuery
		if err := json.NewDecoder(str).Decode(&q); err != nil {
			log.Printf("repquery: bad request from %s: %v", str.Conn().RemotePeer(), err)
			return
		}
		rec, err := s.GetScore(q.IP)
		if err != nil {
			log.Printf("repquery: store error for %s: %v", q.IP, err)
			return
		}
		// Empty record → empty ScoreEntry (LastSeen zero) means "not found".
		if err := json.NewEncoder(str).Encode(EntryFromRecord(q.IP, rec)); err != nil {
			log.Printf("repquery: write answer for %s: %v", q.IP, err)
		}
	})
}
