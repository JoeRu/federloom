package dnsbl

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/store"
)

// responseRecorder captures the DNS reply written by the handler.
type responseRecorder struct {
	msg *dns.Msg
}

func (r *responseRecorder) LocalAddr() net.Addr          { return &net.UDPAddr{} }
func (r *responseRecorder) RemoteAddr() net.Addr         { return &net.UDPAddr{} }
func (r *responseRecorder) WriteMsg(m *dns.Msg) error    { r.msg = m; return nil }
func (r *responseRecorder) Write(b []byte) (int, error)  { return 0, nil }
func (r *responseRecorder) Close() error                 { return nil }
func (r *responseRecorder) TsigStatus() error            { return nil }
func (r *responseRecorder) TsigTimersOnly(bool)          {}
func (r *responseRecorder) Hijack()                      {}

// testStore is a map-backed StoreReader for tests.
type testStore struct {
	data map[string]store.ScoreRecord
}

func (ts *testStore) GetScore(ip string) (store.ScoreRecord, error) {
	rec, ok := ts.data[ip]
	if !ok {
		return store.ScoreRecord{}, nil // zero value: LastSeen.IsZero() == true
	}
	return rec, nil
}

func newTestServer(zone string, threshold float64) (*Server, *testStore) {
	ts := &testStore{data: make(map[string]store.ScoreRecord)}
	cfg := config.DNSBLConfig{
		Addr: ":5353",
		Zone: zone,
	}
	repCfg := config.ReputationConfig{BlockThreshold: threshold}
	srv := New(cfg, ts, repCfg)
	return srv, ts
}

func query(srv *Server, qname string, qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	rec := &responseRecorder{}
	srv.handleDNS(rec, req)
	return rec.msg
}

func TestListedIPReturnsA127(t *testing.T) {
	srv, ts := newTestServer("dnsbl.test.", 75)
	ts.data["1.2.3.4"] = store.ScoreRecord{
		Score:    90,
		LastSeen: time.Now(),
		Reasons:  []string{"smtp-auth-bruteforce"},
	}

	resp := query(srv, "4.3.2.1.dnsbl.test.", dns.TypeA)
	if resp == nil {
		t.Fatal("handler wrote no response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode: got %d, want NOERROR (0)", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("no answer records")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("first answer is %T, want *dns.A", resp.Answer[0])
	}
	if !a.A.Equal(net.ParseIP("127.0.0.2")) {
		t.Errorf("A record: got %s, want 127.0.0.2", a.A)
	}
}

func TestListedIPTypeAIncludesTXT(t *testing.T) {
	srv, ts := newTestServer("dnsbl.test.", 75)
	ts.data["10.0.0.1"] = store.ScoreRecord{
		Score:    85,
		LastSeen: time.Now(),
		Reasons:  []string{"smtp-auth-bruteforce", "imap-auth-bruteforce"},
	}

	resp := query(srv, "1.0.0.10.dnsbl.test.", dns.TypeA)
	if resp == nil {
		t.Fatal("handler wrote no response")
	}
	hasTXT := false
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			hasTXT = true
			if len(txt.Txt) == 0 {
				t.Error("TXT record is empty")
			}
		}
	}
	if !hasTXT {
		t.Error("TypeA response missing TXT record for listed IP")
	}
}

func TestListedIPTypeTXT(t *testing.T) {
	srv, ts := newTestServer("dnsbl.test.", 75)
	ts.data["5.6.7.8"] = store.ScoreRecord{
		Score:    80,
		LastSeen: time.Now(),
		Reasons:  []string{"smtp-spamtrap"},
	}

	resp := query(srv, "8.7.6.5.dnsbl.test.", dns.TypeTXT)
	if resp == nil {
		t.Fatal("handler wrote no response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode: got %d, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("no answer for TypeTXT query")
	}
}

func TestUnlistedIPBelowThreshold(t *testing.T) {
	srv, ts := newTestServer("dnsbl.test.", 75)
	ts.data["9.9.9.9"] = store.ScoreRecord{
		Score:    40, // below threshold
		LastSeen: time.Now(),
	}

	resp := query(srv, "9.9.9.9.dnsbl.test.", dns.TypeA)
	if resp == nil {
		t.Fatal("handler wrote no response")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: got %d, want NXDOMAIN (3)", resp.Rcode)
	}
}

func TestUnknownIPIsNXDOMAIN(t *testing.T) {
	srv, _ := newTestServer("dnsbl.test.", 75)

	resp := query(srv, "1.1.1.1.dnsbl.test.", dns.TypeA)
	if resp == nil {
		t.Fatal("handler wrote no response")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode: got %d, want NXDOMAIN (3)", resp.Rcode)
	}
}

func TestMinScoreFallsBackToBlockThreshold(t *testing.T) {
	// MinScore == 0 should use repCfg.BlockThreshold (75)
	srv, ts := newTestServer("dnsbl.test.", 75)
	ts.data["2.2.2.2"] = store.ScoreRecord{
		Score:    74, // just below threshold
		LastSeen: time.Now(),
	}

	resp := query(srv, "2.2.2.2.dnsbl.test.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("score 74 with threshold 75: expected NXDOMAIN, got rcode %d", resp.Rcode)
	}

	ts.data["3.3.3.3"] = store.ScoreRecord{
		Score:    75, // at threshold — should be listed
		LastSeen: time.Now(),
	}
	resp = query(srv, "3.3.3.3.dnsbl.test.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("score 75 with threshold 75: expected NOERROR, got rcode %d", resp.Rcode)
	}
}

func TestZoneNormalisationTrailingDot(t *testing.T) {
	// Zone without trailing dot should still work
	ts := &testStore{data: make(map[string]store.ScoreRecord)}
	ts.data["1.2.3.4"] = store.ScoreRecord{Score: 90, LastSeen: time.Now()}

	cfg := config.DNSBLConfig{Addr: ":5353", Zone: "dnsbl.test"} // no trailing dot
	srv := New(cfg, ts, config.ReputationConfig{BlockThreshold: 75})

	resp := query(srv, "4.3.2.1.dnsbl.test.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("zone without trailing dot: expected NOERROR, got rcode %d", resp.Rcode)
	}
}

func TestStartDisabledNoOp(t *testing.T) {
	ts := &testStore{data: make(map[string]store.ScoreRecord)}
	cfg := config.DNSBLConfig{Addr: "", Zone: ""} // disabled
	srv := New(cfg, ts, config.ReputationConfig{})
	// Must not panic.
	srv.Start(nil) //nolint:staticcheck — nil ctx is OK for no-op path
}
