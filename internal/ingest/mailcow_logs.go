package ingest

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"os/exec"
	"regexp"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// logFetcher retrieves container log lines since a given RFC3339 timestamp.
// Injectable so tests can stub without a running Docker daemon.
type logFetcher func(ctx context.Context, container, since string) ([]byte, error)

// dockerFetch is the production logFetcher.
func dockerFetch(ctx context.Context, container, since string) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", "logs", "--since", since, container).CombinedOutput()
}

var (
	// postfixSASLRe matches Postfix SASL auth failures.
	// Handles both "unknown[IP]" and "hostname[IP]" client formats.
	postfixSASLRe = regexp.MustCompile(`\[((?:\d{1,3}\.){3}\d{1,3})\]: SASL \S+ authentication failed`)

	// dovecotAuthRe matches Dovecot IMAP/POP3 auth-failed disconnect lines.
	// Capture group 1 = protocol ("imap" or "pop3"), group 2 = remote IP.
	dovecotAuthRe = regexp.MustCompile(`(imap|pop3)-login: Disconnected \(auth failed[^)]*\).*?rip=((?:\d{1,3}\.){3}\d{1,3}),`)
)

// MailcowLogs reads Postfix and Dovecot container logs via "docker logs --since"
// and emits proto.Events for SMTP-AUTH and IMAP/POP3 brute-force attempts.
type MailcowLogs struct {
	cfg     config.MailcowConfig
	selfID  string
	fetcher logFetcher
}

// Compile-time check.
var _ Source = (*MailcowLogs)(nil)

// NewMailcow creates a MailcowLogs adapter using the real Docker log fetcher.
func NewMailcow(cfg config.MailcowConfig, selfID string) *MailcowLogs {
	return NewMailcowWithFetcher(cfg, selfID, dockerFetch)
}

// NewMailcowWithFetcher creates a MailcowLogs adapter with a custom log fetcher.
// Use this in tests to inject a stub without a running Docker daemon.
func NewMailcowWithFetcher(cfg config.MailcowConfig, selfID string, f logFetcher) *MailcowLogs {
	if cfg.PostfixContainer == "" {
		cfg.PostfixContainer = "mailcowdockerized-postfix-1"
	}
	if cfg.DovecotContainer == "" {
		cfg.DovecotContainer = "mailcowdockerized-dovecot-1"
	}
	return &MailcowLogs{cfg: cfg, selfID: selfID, fetcher: f}
}

func (m *MailcowLogs) Name() string { return "mailcow" }

// Start launches the polling goroutine and returns the event channel.
func (m *MailcowLogs) Start(ctx context.Context) (<-chan proto.Event, error) {
	ch := make(chan proto.Event, 64)
	go m.run(ctx, ch)
	return ch, nil
}

func (m *MailcowLogs) run(ctx context.Context, ch chan<- proto.Event) {
	defer close(ch)

	pollInterval := m.cfg.PollInterval.Duration
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}

	// Look back one interval on first poll to catch events just before startup.
	since := time.Now().Add(-pollInterval).UTC().Format(time.RFC3339)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			nextSince := now.UTC().Format(time.RFC3339)
			m.pollPostfix(ctx, since, ch)
			m.pollDovecot(ctx, since, ch)
			since = nextSince
		}
	}
}

func (m *MailcowLogs) pollPostfix(ctx context.Context, since string, ch chan<- proto.Event) {
	data, err := m.fetcher(ctx, m.cfg.PostfixContainer, since)
	if err != nil {
		log.Printf("ingest/mailcow: postfix fetch: %v", err)
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		sub := postfixSASLRe.FindSubmatch(scanner.Bytes())
		if sub == nil {
			continue
		}
		ip := string(sub[1])
		select {
		case ch <- proto.Event{IP: ip, Reason: "smtp-auth-bruteforce", Timestamp: time.Now(), ReporterID: m.selfID}:
		case <-ctx.Done():
			return
		default:
			log.Printf("ingest/mailcow: channel full, dropping %s", ip)
		}
	}
}

func (m *MailcowLogs) pollDovecot(ctx context.Context, since string, ch chan<- proto.Event) {
	data, err := m.fetcher(ctx, m.cfg.DovecotContainer, since)
	if err != nil {
		log.Printf("ingest/mailcow: dovecot fetch: %v", err)
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		sub := dovecotAuthRe.FindSubmatch(scanner.Bytes())
		if sub == nil {
			continue
		}
		proto_ := string(sub[1]) // "imap" or "pop3"
		ip := string(sub[2])
		reason := proto_ + "-auth-bruteforce"
		select {
		case ch <- proto.Event{IP: ip, Reason: reason, Timestamp: time.Now(), ReporterID: m.selfID}:
		case <-ctx.Done():
			return
		default:
			log.Printf("ingest/mailcow: channel full, dropping %s", ip)
		}
	}
}
