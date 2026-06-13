package node

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/enforce"
	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/internal/transport"
	"github.com/JoeRu/swarmguard/internal/trust"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// testNode builds a Node with a temp store, no transport, and a permissive
// block threshold so the enforce sink is never invoked.
func testNode(t *testing.T) (*Node, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.BlockThreshold = 1000

	s, err := store.Open(dir + "/db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ts := trust.NewStore(cfg.TrustAnchorsFile(), cfg.TrustCertsFile(), cfg.Trust.StrangerWeight)
	ts.SetReloadInterval(0)

	return &Node{
		cfg:        cfg,
		store:      s,
		rep:        reputation.New(s, 7*24*time.Hour, cfg.Trust.StrangerScoreCap),
		neverblock: enforce.NewNeverBlockList(nil),
		trust:      ts,
		selfID:     "12D3KooWself",
	}, dir
}

// TestSpoofedReporterDropped: ReporterID != verified publisher → event ignored.
func TestSpoofedReporterDropped(t *testing.T) {
	n, _ := testNode(t)
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "192.0.2.10", Reason: "ssh-probe", ReporterID: "12D3KooWvictim"},
		From:  "12D3KooWattacker",
	})
	rec, err := n.rep.GetRecord("192.0.2.10")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if !rec.LastSeen.IsZero() {
		t.Error("spoofed event reached the reputation engine")
	}
}

// TestVouchedReporterScoresAsAnchored: a valid on-wire vouch from an anchored
// Person resolves to the anchor weight and group.
func TestVouchedReporterScoresAsAnchored(t *testing.T) {
	n, dir := testNode(t)

	priv, err := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	if err := trust.SaveAnchors(n.cfg.TrustAnchorsFile(), []trust.Anchor{{
		Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "self-added",
	}}); err != nil {
		t.Fatalf("save anchors: %v", err)
	}

	cert := identity.IssueCert(priv, "12D3KooWjoA", time.Now().Add(time.Hour))
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "192.0.2.11", Reason: "ssh-probe", ReporterID: "12D3KooWjoA", Vouch: &cert},
		From:  "12D3KooWjoA",
	})

	rec, _ := n.rep.GetRecord("192.0.2.11")
	if len(rec.Groups) != 1 || rec.Groups[0] != "jo" {
		t.Errorf("Groups = %v, want [jo]", rec.Groups)
	}
	if rec.StrangerSeen {
		t.Error("vouched reporter recorded as stranger")
	}
}

// TestVouchReplayedCertIsStranger: a cert for peer A attached by peer B is
// rejected — B stays a stranger.
func TestVouchReplayedCertIsStranger(t *testing.T) {
	n, dir := testNode(t)

	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	_ = trust.SaveAnchors(n.cfg.TrustAnchorsFile(), []trust.Anchor{{
		Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "self-added",
	}})

	certForA := identity.IssueCert(priv, "12D3KooWjoA", time.Now().Add(time.Hour))
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "192.0.2.12", Reason: "ssh-probe", ReporterID: "12D3KooWeve", Vouch: &certForA},
		From:  "12D3KooWeve",
	})

	rec, _ := n.rep.GetRecord("192.0.2.12")
	if len(rec.Groups) != 0 {
		t.Errorf("replayed cert produced anchored groups: %v", rec.Groups)
	}
	if !rec.StrangerSeen {
		t.Error("event was dropped entirely; replayed-cert events should score as stranger")
	}
}
