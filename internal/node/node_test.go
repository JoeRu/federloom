package node

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/enforce"
	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/rules"
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

	ts := trust.NewStore(cfg.TrustAnchorsFile(), cfg.TrustCertsFile(), cfg.TrustBlockedPeersFile(), cfg.Trust.StrangerWeight)
	ts.SetReloadInterval(0)

	return &Node{
		cfg:        cfg,
		store:      s,
		rep:        reputation.New(s, 7*24*time.Hour, cfg.Trust.StrangerScoreCap),
		neverblock: enforce.NewNeverBlockList(nil),
		trust:      ts,
		selfID:     "12D3KooWself",
		rules:      rules.Load("", cfg.Reputation.BlockThreshold),
		burst:      rules.NewBurstStore(),
	}, dir
}

// TestNodeAcceptsMailcowAndSpamtrapConfig verifies that New() wires MailcowLogs
// and Spamtrap sources when their configs have Enabled: true.
func TestNodeAcceptsMailcowAndSpamtrapConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.BlockThreshold = 1000
	cfg.Ingest.MailcowLogs.Enabled = true
	cfg.Ingest.MailcowLogs.PostfixContainer = "test-postfix"
	cfg.Ingest.MailcowLogs.DovecotContainer = "test-dovecot"
	cfg.Ingest.Spamtrap.Enabled = true
	cfg.Ingest.Spamtrap.LogFile = filepath.Join(dir, "spamtrap.log")

	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New with mailcow+spamtrap config: %v", err)
	}
	defer n.CloseStores()

	names := make([]string, 0, len(n.sources))
	for _, src := range n.sources {
		names = append(names, src.Name())
	}
	hasMail := false
	hasSpam := false
	for _, name := range names {
		if name == "mailcow" {
			hasMail = true
		}
		if name == "spamtrap" {
			hasSpam = true
		}
	}
	if !hasMail {
		t.Errorf("mailcow source not wired; sources = %v", names)
	}
	if !hasSpam {
		t.Errorf("spamtrap source not wired; sources = %v", names)
	}
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

// TestProcessLocalDropsInvalidIP verifies that processLocal silently drops events
// whose IP field is not a bare IPv4/IPv6 address (CIDR, hostname, newline-embedded).
func TestProcessLocalDropsInvalidIP(t *testing.T) {
	cases := []string{
		"0.0.0.0/0",        // CIDR — block-all nftables attack
		"1.2.3.4\n5.6.7.8", // newline injection
		"example.com",      // hostname
		"",                 // empty
	}
	for _, ip := range cases {
		ip := ip
		t.Run(ip, func(t *testing.T) {
			n, _ := testNode(t)
			n.processLocal(context.Background(), proto.Event{IP: ip, Reason: "ssh-probe"})
			rec, _ := n.rep.GetRecord(ip)
			if !rec.LastSeen.IsZero() {
				t.Errorf("invalid IP %q was recorded in reputation store", ip)
			}
		})
	}
}

// TestProcessRemoteDropsInvalidIP verifies that ProcessRemote silently drops events
// whose IP field is not a bare IPv4/IPv6 address.
func TestProcessRemoteDropsInvalidIP(t *testing.T) {
	cases := []string{
		"0.0.0.0/0",
		"1.2.3.4\n5.6.7.8",
		"example.com",
		"",
	}
	for _, ip := range cases {
		ip := ip
		t.Run(ip, func(t *testing.T) {
			n, _ := testNode(t)
			n.ProcessRemote(transport.ReceivedEvent{
				Event: proto.Event{IP: ip, Reason: "ssh-probe", ReporterID: "12D3KooWpeer"},
				From:  "12D3KooWpeer",
			})
			rec, _ := n.rep.GetRecord(ip)
			if !rec.LastSeen.IsZero() {
				t.Errorf("invalid IP %q was recorded in reputation store", ip)
			}
		})
	}
}

// TestProcessLocalAcceptsValidIP is the control: a valid bare IP must be recorded.
func TestProcessLocalAcceptsValidIP(t *testing.T) {
	n, _ := testNode(t)
	n.processLocal(context.Background(), proto.Event{IP: "203.0.113.1", Reason: "ssh-probe"})
	rec, err := n.rep.GetRecord("203.0.113.1")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.LastSeen.IsZero() {
		t.Error("valid IP was not recorded in reputation store")
	}
}

func TestProcessRemoteScoresValidEventWithOriginTrace(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	// We can't easily inspect the event after processLocal without a transport.
	// Instead verify via published-event capture — use the exported BroadcastCh helper.
	// Since we have no transport, just confirm the node starts without error.
	// The OriginTrace content is validated in integration tests.
	// Here we at least confirm processLocal does not panic with selfID="".
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:          "203.0.113.1",
			Reason:      "ssh-probe",
			ReporterID:  "12D3KooWtestpeer",
			OriginTrace: []string{"12D3KooWtestpeer"},
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ := n.GetScore("203.0.113.1")
	if rec.LastSeen.IsZero() {
		t.Error("expected score recorded for valid remote event")
	}
}

func TestProcessRemoteDropsFeedbackLoop(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	// When selfID is "" (solo mode), no loop guard fires. Test the logic
	// by injecting an event where the OriginTrace contains the node's own ID
	// via SelfID accessor.
	selfID := n.SelfID()
	if selfID == "" {
		t.Skip("no selfID in solo mode — feedback loop guard requires transport")
	}
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:          "203.0.113.2",
			Reason:      "ssh-probe",
			ReporterID:  "12D3KooWtestpeer",
			OriginTrace: []string{"12D3KooWtestpeer", selfID}, // selfID in trace = loop
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ := n.GetScore("203.0.113.2")
	if !rec.LastSeen.IsZero() {
		t.Error("event with selfID in OriginTrace should have been dropped")
	}
}

func TestProcessRemoteDropsOverlongOriginTrace(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	longTrace := make([]string, 9) // 9 > maxOriginTraceLen(8)
	for i := range longTrace {
		longTrace[i] = fmt.Sprintf("12D3KooWhop%d", i)
	}
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:          "203.0.113.3",
			Reason:      "ssh-probe",
			ReporterID:  "12D3KooWtestpeer",
			OriginTrace: longTrace,
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ := n.GetScore("203.0.113.3")
	if !rec.LastSeen.IsZero() {
		t.Error("event with overlong OriginTrace should have been dropped")
	}
}
