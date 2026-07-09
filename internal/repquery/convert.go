// Package repquery implements the on-demand federated reputation query protocol
// (spec §11.4, sub-project E3): a libp2p request/response so a node can fetch an
// IP's reputation from configured aggregator peers when it has no local record.
package repquery

import (
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// EntryFromRecord projects a local ScoreRecord onto the wire ScoreEntry (the
// answer). Tracking-only fields (ReporterIDs/Groups/StrangerContrib) are never
// shared. Disputes is 0 (not tracked yet).
func EntryFromRecord(ip string, r store.ScoreRecord) proto.ScoreEntry {
	return proto.ScoreEntry{
		IP:            ip,
		Score:         r.Score,
		Corroboration: r.Corroboration,
		FirstSeen:     r.FirstSeen,
		LastSeen:      r.LastSeen,
		Reasons:       r.Reasons,
	}
}

// RecordFromEntry projects a received ScoreEntry back onto a ScoreRecord so the
// DNSBL/API read path (which speaks ScoreRecord) can consume a federated answer.
func RecordFromEntry(e proto.ScoreEntry) store.ScoreRecord {
	return store.ScoreRecord{
		Score:         e.Score,
		Corroboration: e.Corroboration,
		FirstSeen:     e.FirstSeen,
		LastSeen:      e.LastSeen,
		Reasons:       e.Reasons,
	}
}
