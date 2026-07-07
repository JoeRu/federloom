//go:build adversarial

package adversarial

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/internal/trust"
	"github.com/JoeRu/federloom/pkg/proto"
)

// injectionRules is a minimal rule file exercising the two block paths a remote
// stranger could previously abuse: a corroboration:1 block and a burst block.
const injectionRules = `
- name: honeypot-shell-exec
  reason: ssh-post-auth-command
  min_corroboration: 1
  action: block
- name: ssh-brute-burst
  reason: ssh-auth-bruteforce
  min_burst: 15
  burst_window: 10m
  action: block
`

// newInjectionNode builds a solo Node with injectionRules loaded and a mock
// sink installed so Block calls are observable. Returns the node, its data dir,
// and the mock sink.
func newInjectionNode(t *testing.T) (*node.Node, string, *mockSink) {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(injectionRules), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.RulesFile = rulesPath

	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	n.SetTrustReloadInterval(0)
	sink := &mockSink{}
	n.SetSinkForTest(sink)
	t.Cleanup(func() { n.CloseStores() })
	return n, dir, sink
}

// TestStrangerCannotInjectCorroborationBlock: a single un-anchored remote event
// matching a min_corroboration:1 block rule must NOT cause a block (P0-1).
func TestStrangerCannotInjectCorroborationBlock(t *testing.T) {
	n, _, sink := newInjectionNode(t)
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "203.0.113.10", Reason: "ssh-post-auth-command", ReporterID: "stranger-peer"},
		From:  "stranger-peer",
	})
	if len(sink.blocked) != 0 {
		t.Errorf("stranger triggered %d block(s) via min_corroboration:1; want 0", len(sink.blocked))
	}
}

// TestStrangerCannotInjectBurstBlock: 15 un-anchored remote events must NOT trip
// the burst block rule, because strangers no longer feed the burst window (P0-2).
func TestStrangerCannotInjectBurstBlock(t *testing.T) {
	n, _, sink := newInjectionNode(t)
	for i := 0; i < 15; i++ {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: "203.0.113.11", Reason: "ssh-auth-bruteforce", ReporterID: "stranger-peer"},
			From:  "stranger-peer",
		})
	}
	if len(sink.blocked) != 0 {
		t.Errorf("stranger burst triggered %d block(s); want 0", len(sink.blocked))
	}
}

// anchoredEvent builds a remote event whose reporter is vouched by an anchored
// Person, so ProcessRemote resolves it as anchored (weight 0.9, group "jo").
func anchoredEvent(t *testing.T, n *node.Node, dir, ip, reason string) transport.ReceivedEvent {
	t.Helper()
	priv, err := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	anchorsPath := filepath.Join(dir, "anchors.json")
	if err := trust.SaveAnchors(anchorsPath, []trust.Anchor{{
		Person:         "jo",
		IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight:         0.9,
		Source:         "self-added",
	}}); err != nil {
		t.Fatalf("save anchors: %v", err)
	}
	const peerID = "anchored-peer-1"
	cert := identity.IssueCert(priv, peerID, time.Now().Add(24*time.Hour))
	return transport.ReceivedEvent{
		Event: proto.Event{IP: ip, Reason: reason, ReporterID: peerID, Vouch: &cert},
		From:  peerID,
	}
}

// TestAnchoredReporterCanBlock: the legit federation path still works — an
// anchored remote reporter's ssh-post-auth-command IS blocked (regression).
func TestAnchoredReporterCanBlock(t *testing.T) {
	n, dir, sink := newInjectionNode(t)
	// SaveAnchors path must match cfg's TrustAnchorsFile; Defaults resolves it
	// under Store.Dir, and anchoredEvent writes anchors.json there.
	re := anchoredEvent(t, n, dir, "203.0.113.12", "ssh-post-auth-command")
	n.ProcessRemote(re)
	if len(sink.blocked) != 1 || sink.blocked[0] != "203.0.113.12" {
		t.Errorf("anchored reporter should block 203.0.113.12; got blocked=%v", sink.blocked)
	}
}

// TestAnchoredBurstStillBlocks: anchored reporters still feed the burst window,
// so 15 anchored ssh-auth-bruteforce events DO block (regression for A2).
func TestAnchoredBurstStillBlocks(t *testing.T) {
	n, dir, sink := newInjectionNode(t)
	// Build the anchored setup + cert ONCE (anchoredEvent generates the Person
	// key and writes anchors.json; calling it in the loop would regenerate the
	// key each iteration). Reuse the same event 15 times to fill the window.
	re := anchoredEvent(t, n, dir, "203.0.113.13", "ssh-auth-bruteforce")
	for i := 0; i < 15; i++ {
		n.ProcessRemote(re)
	}
	if len(sink.blocked) == 0 {
		t.Error("anchored burst of 15 must trip ssh-brute-burst; got 0 blocks")
	}
}
