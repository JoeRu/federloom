package dnsbl

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/store"
)

// StoreReader is the minimal store interface the DNSBL server needs.
// Narrower than api.StoreReader (no ScanScores) — only point lookups required.
type StoreReader interface {
	GetScore(ip string) (store.ScoreRecord, error)
}

// Server is the optional embedded DNSBL DNS server.
// All methods are safe to call on a nil or zero-addr server (no-op).
type Server struct {
	cfg    config.DNSBLConfig
	store  StoreReader
	repCfg config.ReputationConfig
	zone   string // normalised FQDN, e.g. "dnsbl.mail.example.com."
	mux    *dns.ServeMux
}

// New creates a Server. Call Start to begin serving.
// If cfg.Zone is empty, no DNS handler is registered and Start is a no-op.
func New(cfg config.DNSBLConfig, s StoreReader, repCfg config.ReputationConfig) *Server {
	srv := &Server{
		cfg:    cfg,
		store:  s,
		repCfg: repCfg,
		mux:    dns.NewServeMux(),
	}
	if cfg.Zone != "" {
		srv.zone = dns.Fqdn(strings.ToLower(cfg.Zone))
		srv.mux.HandleFunc(srv.zone, srv.handleDNS)
	}
	return srv
}

// Start starts the DNSBL server on both UDP and TCP.
// It is a no-op when cfg.Addr or cfg.Zone is empty, or when s is nil.
// The servers shut down when ctx is cancelled.
func (s *Server) Start(ctx context.Context) {
	if s == nil || s.cfg.Addr == "" || s.cfg.Zone == "" {
		return
	}

	udpSrv := &dns.Server{Addr: s.cfg.Addr, Net: "udp", Handler: s.mux}
	tcpSrv := &dns.Server{Addr: s.cfg.Addr, Net: "tcp", Handler: s.mux}

	go func() {
		log.Printf("dnsbl: listening on %s (UDP+TCP) zone %s", s.cfg.Addr, s.zone)
		if err := udpSrv.ListenAndServe(); err != nil {
			log.Printf("dnsbl: UDP error: %v", err)
		}
	}()
	go func() {
		if err := tcpSrv.ListenAndServe(); err != nil {
			log.Printf("dnsbl: TCP error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = udpSrv.ShutdownContext(shutCtx)
		_ = tcpSrv.ShutdownContext(shutCtx)
	}()
}

// handleDNS is the dns.HandlerFunc for the configured zone.
// It parses the reversed-IP DNSBL query, looks up the score, and responds
// with A 127.0.0.2 + TXT for listed IPs, or NXDOMAIN for unlisted/unknown IPs.
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(q.Name)

	// Strip zone suffix to extract reversed IP, e.g. "4.3.2.1" from "4.3.2.1.dnsbl.test."
	suffix := "." + s.zone
	if !strings.HasSuffix(qname, suffix) {
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}
	reversed := strings.TrimSuffix(qname, suffix)

	// Reverse octets: "4.3.2.1" → "1.2.3.4"
	parts := strings.Split(reversed, ".")
	if len(parts) != 4 {
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	ip := strings.Join(parts, ".")

	rec, err := s.store.GetScore(ip)
	if err != nil || rec.LastSeen.IsZero() {
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}

	minScore := s.cfg.MinScore
	if minScore == 0 {
		minScore = s.repCfg.BlockThreshold
	}

	if rec.Score < minScore {
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}

	// Build TXT payload regardless of query type (used in both A and TXT responses).
	txtPayload := fmt.Sprintf("score=%.1f reasons=%s", rec.Score, strings.Join(rec.Reasons, ","))

	switch q.Qtype {
	case dns.TypeA:
		m.Answer = append(m.Answer,
			&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.2").To4(),
			},
			&dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{txtPayload},
			},
		)
	case dns.TypeTXT:
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{txtPayload},
		})
	// Other query types: NOERROR with empty answer section (RFC-compliant).
	}

	_ = w.WriteMsg(m)
}
