package repquery

import (
	"strconv"
	"time"

	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// maxEvidenceFolds bounds how many synthetic votes an EvidenceAggregate can
// drive — the logistic score saturates within a handful, so a large attacker-
// supplied "groups" count buys nothing but CPU. Cap it.
const maxEvidenceFolds = 64

// maxWeightScenario returns the scenario with the highest local weight (the vote
// reason for the recompute). "" if scenarios is empty (weightFor("") = default).
func maxWeightScenario(scenarios []string) string {
	best := ""
	bestW := -1.0
	for _, s := range scenarios {
		if w := reputation.WeightFor(s); w > bestW {
			bestW, best = w, s
		}
	}
	return best
}

// RecordFromEvidence recomputes a local ScoreRecord from a federated
// EvidenceAggregate using the CONSUMER's own parameters (§8: recomputed under
// your own rules). It folds synthetic anchored votes — one per counted group —
// plus one capped stranger vote if strangers were present, through the same
// reputation.Accumulate math native events use.
//
// CRITICAL INVARIANT: the returned record's Groups/ReporterIDs are empty and
// Corroboration is 0. The synthetic anchored votes drive the SCORE only; the
// answer must never satisfy the anchored-corroboration block backstop
// (len(rec.Groups) > 0). The score alone is advisory (DNSBL/API), threshold-governed.
func RecordFromEvidence(ev proto.EvidenceAggregate, now time.Time, halfLife time.Duration, strangerCap, federationDiscount, diversityRepeat, disputeWeight float64) store.ScoreRecord {
	if ev.WindowLast.IsZero() {
		return store.ScoreRecord{} // not found
	}
	weight := ev.EvidenceWeight
	if weight != weight || weight < 0 { // NaN or negative -> 0
		weight = 0
	}
	if weight > 1 {
		weight = 1
	}
	trust := weight * federationDiscount
	reason := maxWeightScenario(ev.Scenarios)

	groups := ev.DiversityBuckets["groups"]
	if groups > maxEvidenceFolds {
		groups = maxEvidenceFolds
	}
	if groups < 0 {
		groups = 0
	}
	// Subnet diversity caps how many group-votes count at FULL weight (§4.2):
	// the rest are damped by Accumulate's own repeat mechanic. subnets==0 (older
	// aggregate) → treat as 1 (a known IP came from at least one subnet).
	subnets := ev.DiversityBuckets["subnets"]
	if subnets < 1 {
		subnets = 1
	}
	fullVotes := groups
	if subnets < fullVotes {
		fullVotes = subnets
	}

	folded := store.ScoreRecord{}
	for i := 0; i < groups; i++ {
		// First `fullVotes` folds get distinct synthetic subnets (full weight);
		// the rest share one subnet so Accumulate damps them as repeats.
		subnet := "fed-" + strconv.Itoa(i)
		if i >= fullVotes {
			subnet = "fed-repeat"
		}
		folded = reputation.Accumulate(folded, reputation.Observation{
			Reason: reason, ReporterID: "fed", Group: "fed", Subnet: subnet, Trust: trust, Anchored: true,
		}, ev.WindowLast, halfLife, strangerCap, diversityRepeat)
	}
	if ev.StrangersPresent {
		folded = reputation.Accumulate(folded, reputation.Observation{
			Reason: reason, ReporterID: "fed-stranger", Trust: trust, Anchored: false,
		}, ev.WindowLast, halfLife, strangerCap, 1.0)
	}

	disputeSubnets := ev.DiversityBuckets["dispute_subnets"]
	if disputeSubnets > maxEvidenceFolds {
		disputeSubnets = maxEvidenceFolds
	}
	for i := 0; i < disputeSubnets; i++ {
		folded = reputation.ApplyDispute(folded, reputation.Observation{
			ReporterID: "fed-dispute", Subnet: "fed-d" + strconv.Itoa(i), Trust: trust, Anchored: true,
		}, ev.WindowLast, halfLife, disputeWeight, strangerCap, diversityRepeat)
	}

	score := reputation.DecayScore(folded.Score, ev.WindowLast, now, halfLife)
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	// Rebuild a record that carries the recomputed SCORE and provenance-safe
	// metadata ONLY — never Groups/ReporterIDs/Corroboration (the invariant).
	return store.ScoreRecord{
		Score:     score,
		Reasons:   append([]string(nil), ev.Scenarios...),
		FirstSeen: ev.WindowFirst,
		LastSeen:  ev.WindowLast,
	}
}
