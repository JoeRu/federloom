//go:build adversarial

package adversarial

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/enforce"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

// blockForCall records a single BlockFor(ip, ttl) invocation.
type blockForCall struct {
	IP  string
	TTL time.Duration
}

// mockSink records Block/Unblock calls without touching any real firewall.
type mockSink struct {
	blocked    []string
	unblocked  []string
	blockedFor []blockForCall
}

func (m *mockSink) Name() string                  { return "mock" }
func (m *mockSink) Start(_ context.Context) error { return nil }
func (m *mockSink) Block(ip string) error         { m.blocked = append(m.blocked, ip); return nil }
func (m *mockSink) BlockFor(ip string, ttl time.Duration) error {
	m.blockedFor = append(m.blockedFor, blockForCall{ip, ttl})
	return nil
}
func (m *mockSink) Unblock(ip string) error { m.unblocked = append(m.unblocked, ip); return nil }
func (m *mockSink) Close() error            { return nil }

var _ enforce.Sink = (*mockSink)(nil)

// TestNeverBlockPoisoningRFC1918 verifies that a malicious remote peer flooding
// reports for RFC1918, loopback, and CGNAT addresses cannot cause any block
// action to be applied (spec §6.2 / CLAUDE.md invariant 3).
func TestNeverBlockPoisoningRFC1918(t *testing.T) {
	protected := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"127.0.0.1",
		"100.64.0.1", // CGNAT
	}

	nbl := enforce.NewNeverBlockList(nil)

	for _, ip := range protected {
		ip := ip
		t.Run(ip, func(t *testing.T) {
			s, err := store.Open(t.TempDir())
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			defer s.Close()

			engine := reputation.New(s, 7*24*time.Hour, 15, 0.15, 10)
			sink := &mockSink{}

			for i := 0; i < 10; i++ {
				peerID := fmt.Sprintf("malicious-peer-%d", i)
				score, err := engine.Record(ip, "ssh-auth-success", peerID, 1.0, peerID, "", true)
				if err != nil {
					t.Fatalf("Record[%d]: %v", i, err)
				}
				if score >= 75.0 && !nbl.Contains(ip) {
					if err := sink.Block(ip); err != nil {
						t.Fatalf("Block: %v", err)
					}
				}
			}

			if len(sink.blocked) != 0 {
				t.Errorf("protected IP %q was blocked %d time(s); neverblock gate must prevent all blocks",
					ip, len(sink.blocked))
			}
		})
	}
}

// TestNeverBlockPoisoningLoopback verifies the neverblock gate for IPv6 loopback
// and link-local addresses (spec §6.2 / CLAUDE.md invariant 3).
func TestNeverBlockPoisoningLoopback(t *testing.T) {
	protected := []string{
		"::1",     // IPv6 loopback
		"fe80::1", // IPv6 link-local
	}

	nbl := enforce.NewNeverBlockList(nil)

	for _, ip := range protected {
		ip := ip
		t.Run(ip, func(t *testing.T) {
			s, err := store.Open(t.TempDir())
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			defer s.Close()

			engine := reputation.New(s, 7*24*time.Hour, 15, 0.15, 10)
			sink := &mockSink{}

			for i := 0; i < 10; i++ {
				peerID := fmt.Sprintf("malicious-peer-%d", i)
				score, err := engine.Record(ip, "ssh-auth-success", peerID, 1.0, peerID, "", true)
				if err != nil {
					t.Fatalf("Record[%d]: %v", i, err)
				}
				if score >= 75.0 && !nbl.Contains(ip) {
					if err := sink.Block(ip); err != nil {
						t.Fatalf("Block: %v", err)
					}
				}
			}

			if len(sink.blocked) != 0 {
				t.Errorf("protected IP %q was blocked %d time(s); neverblock gate must prevent all blocks",
					ip, len(sink.blocked))
			}
		})
	}
}

// TestNeverBlockPublicIPNotProtected is the control test: a genuine public IP
// that exceeds the 75-point threshold IS blocked, confirming the neverblock gate
// does not over-protect legitimate enforcement targets.
func TestNeverBlockPublicIPNotProtected(t *testing.T) {
	const ip = "203.0.113.5"

	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	engine := reputation.New(s, 7*24*time.Hour, 15, 0.15, 10)
	nbl := enforce.NewNeverBlockList(nil)
	sink := &mockSink{}

	// 3 reports with trust=1.0, weight=40 using logistic formula:
	//   after 1: 0 + 1*40*(1-0/100) = 40.0
	//   after 2: 40 + 1*40*(1-40/100) = 40 + 24 = 64.0
	//   after 3: 64 + 1*40*(1-64/100) = 64 + 14.4 = 78.4  → > 75 threshold
	for i := 0; i < 3; i++ {
		peerID := fmt.Sprintf("peer-%d", i)
		score, err := engine.Record(ip, "ssh-auth-success", peerID, 1.0, peerID, "", true)
		if err != nil {
			t.Fatalf("Record[%d]: %v", i, err)
		}
		if score >= 75.0 && !nbl.Contains(ip) {
			if err := sink.Block(ip); err != nil {
				t.Fatalf("Block: %v", err)
			}
		}
	}

	if len(sink.blocked) != 1 {
		t.Errorf("expected 1 block for public IP %q; got %d", ip, len(sink.blocked))
	}
	if len(sink.blocked) == 1 && sink.blocked[0] != ip {
		t.Errorf("blocked wrong IP: want %q, got %q", ip, sink.blocked[0])
	}
}

// TestCIDRInjectionNeverRecorded verifies that a remote attacker publishing
// a CIDR key (e.g. "0.0.0.0/0") cannot inject it into the reputation store.
// The net.ParseIP gate in ProcessRemote rejects any string that is not a valid
// single IP address (spec §6.1 / Vuln 1 adversarial scenario).
func TestCIDRInjectionNeverRecorded(t *testing.T) {
	const cidrKey = "0.0.0.0/0"

	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()

	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.CloseStores()

	// Remote attacker sends 20 events with CIDR as IP field.
	for i := 0; i < 20; i++ {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{
				IP:         cidrKey,
				Reason:     "ssh-probe",
				ReporterID: "12D3KooWattacker",
			},
			From: "12D3KooWattacker",
		})
	}

	// Attempt to retrieve the CIDR key from the store.
	rec, _ := n.GetScore(cidrKey)

	// Assert that the CIDR was never recorded: LastSeen should be zero.
	if !rec.LastSeen.IsZero() {
		t.Errorf("CIDR key %q must not be recorded in store; LastSeen=%v (non-zero)",
			cidrKey, rec.LastSeen)
	}
}
