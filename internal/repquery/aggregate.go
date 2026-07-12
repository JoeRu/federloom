package repquery

import (
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// AggregateFromRecord projects a local ScoreRecord onto the wire EvidenceAggregate
// (spec §7.5). It shares only distinct-reporter COUNTS per bucket — never the
// Groups/ReporterIDs contents themselves (§7.5 "never reporter identity").
func AggregateFromRecord(ip string, r store.ScoreRecord) proto.EvidenceAggregate {
	return proto.EvidenceAggregate{
		IP:          ip,
		Scenarios:   r.Reasons,
		WindowFirst: r.FirstSeen,
		WindowLast:  r.LastSeen, // zero => "not found" sentinel
		DiversityBuckets: map[string]int{
			"groups":    len(r.Groups),
			"reporters": len(r.ReporterIDs),
		},
		StrangersPresent: r.StrangerSeen,
		EvidenceWeight:   1.0,
	}
}
