//go:build adversarial

package adversarial

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

// Ingest sources apply backpressure instead of dropping events on a full
// channel, so a single attacker session that writes hundreds of honeypot lines
// now reaches scoring in full rather than truncated to the channel size. These
// scenarios pin down what that may and may not change: more repetitions from
// the same reporter raise that reporter's own evidence, but never turn into
// extra corroboration votes, an unbounded score, or a block a stranger could
// not otherwise force.

const backpressureBurst = 300

// TestLocalBurstIsOneVoteAndBounded: a full local burst for one IP stays a
// single corroboration vote and the score stays within the scale.
func TestLocalBurstIsOneVoteAndBounded(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	engine := reputation.New(s, 7*24*time.Hour, 15, 0.15, 10)

	const ip, self = "203.0.113.40", "self-peer"
	for i := 0; i < backpressureBurst; i++ {
		// Same arguments node.processLocal uses for its own observations.
		if _, err := engine.Record(ip, "ssh-unknown", self, 1.0, self, "", true); err != nil {
			t.Fatalf("Record[%d]: %v", i, err)
		}
	}
	rec, err := engine.GetRecord(ip)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Corroboration != 1 {
		t.Errorf("local burst corroboration = %d, want 1 (one reporter is one vote)", rec.Corroboration)
	}
	if rec.Score > 100.0001 || rec.Score <= 0 {
		t.Errorf("local burst score = %.4f, want within (0, 100]", rec.Score)
	}
}

// TestForwardedBurstFromAnchoredPeerIsOneVote: when an anchored peer gossips
// its whole (no longer truncated) burst, the receiving node still counts that
// peer once.
func TestForwardedBurstFromAnchoredPeerIsOneVote(t *testing.T) {
	n, dir, _ := newNodeWithRules(t, lowScoreRules)
	const ip = "203.0.113.41"
	re := anchoredEvent(t, n, dir, ip, "ssh-unknown")
	base := time.Now()
	for i := 0; i < backpressureBurst; i++ {
		// Distinct timestamps: these are distinct attempts, not duplicates the
		// dedup cache would collapse.
		re.Event.Timestamp = base.Add(time.Duration(i) * time.Millisecond)
		n.ProcessRemote(re)
	}
	rec, err := n.GetScore(ip)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if rec.Corroboration != 1 {
		t.Errorf("forwarded burst corroboration = %d, want 1", rec.Corroboration)
	}
	if rec.Score > 100.0001 {
		t.Errorf("forwarded burst score = %.4f, want <= 100", rec.Score)
	}
}

// TestStrangerFullBurstCannotBlock: the stranger guarantee holds at burst
// sizes backpressure now lets through (cf. TestStrangerCannotInjectBurstBlock,
// which uses the 15-event rule threshold).
func TestStrangerFullBurstCannotBlock(t *testing.T) {
	n, _, sink := newInjectionNode(t)
	base := time.Now()
	for i := 0; i < backpressureBurst; i++ {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: "203.0.113.42", Reason: "ssh-auth-bruteforce",
				ReporterID: "stranger-peer", Timestamp: base.Add(time.Duration(i) * time.Millisecond)},
			From: "stranger-peer",
		})
	}
	if len(sink.blocked) != 0 {
		t.Errorf("stranger burst of %d triggered %d block(s); want 0", backpressureBurst, len(sink.blocked))
	}
}
