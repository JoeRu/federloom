package ingest

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// fail2banFetcher retrieves the current ban set from a fail2ban container.
// Injectable so tests run without a Docker daemon.
type fail2banFetcher func(ctx context.Context, container string) ([]byte, error)

// dockerBanned is the production fetcher: runs `docker exec <container> fail2ban-client banned`.
func dockerBanned(ctx context.Context, container string) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", "exec", container, "fail2ban-client", "banned").Output()
}

// builtinJailReasons maps common fail2ban jail names (exact) to SwarmGuard reason strings.
var builtinJailReasons = map[string]string{
	"sshd":            "ssh-auth-bruteforce",
	"ssh":             "ssh-auth-bruteforce",
	"postfix":         "smtp-auth-bruteforce",
	"postfix-sasl":    "smtp-auth-bruteforce",
	"dovecot":         "imap-auth-bruteforce",
	"nginx-http-auth": "http-auth-bruteforce",
	"apache-auth":     "http-auth-bruteforce",
	"wordpress":       "http-wp-bruteforce",
	"recidive":        "recidive",
}

// builtinJailPrefixes maps jail name prefixes to reason strings.
// Checked in order after exact matches; first match wins.
// Slice preserves match priority; first prefix wins.
var builtinJailPrefixes = []struct{ prefix, reason string }{
	{"sshd-", "ssh-auth-bruteforce"},
	{"postfix-", "smtp-auth-bruteforce"},
	{"dovecot-", "imap-auth-bruteforce"},
	{"nginx-", "http-auth-bruteforce"},
	{"apache-", "http-auth-bruteforce"},
	{"wp-", "http-wp-bruteforce"},
}

// Fail2Ban polls a fail2ban Docker container for banned IPs and emits proto.Events.
type Fail2Ban struct {
	cfg     config.Fail2BanConfig
	selfID  string
	fetcher fail2banFetcher
}

// Compile-time check: Fail2Ban must implement Source.
var _ Source = (*Fail2Ban)(nil)

// NewFail2Ban creates a Fail2Ban adapter using the real Docker fetcher.
func NewFail2Ban(cfg config.Fail2BanConfig, selfID string) *Fail2Ban {
	return NewFail2BanWithFetcher(cfg, selfID, dockerBanned)
}

// NewFail2BanWithFetcher creates a Fail2Ban adapter with a custom fetcher.
// Use this in tests to inject a stub without a running Docker daemon.
func NewFail2BanWithFetcher(cfg config.Fail2BanConfig, selfID string, f fail2banFetcher) *Fail2Ban {
	if cfg.Container == "" {
		cfg.Container = "fail2ban"
	}
	return &Fail2Ban{cfg: cfg, selfID: selfID, fetcher: f}
}

func (f *Fail2Ban) Name() string { return "fail2ban" }

// Start launches the polling goroutine and returns the event channel.
func (f *Fail2Ban) Start(ctx context.Context) (<-chan proto.Event, error) {
	ch := make(chan proto.Event, 64)
	go f.run(ctx, ch)
	return ch, nil
}

func (f *Fail2Ban) run(ctx context.Context, ch chan<- proto.Event) {
	defer close(ch)

	pollInterval := f.cfg.PollInterval.Duration
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}

	seen := make(map[string]struct{})

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.poll(ctx, seen, ch)
		}
	}
}

func (f *Fail2Ban) poll(ctx context.Context, seen map[string]struct{}, ch chan<- proto.Event) {
	data, err := f.fetcher(ctx, f.cfg.Container)
	if err != nil {
		log.Printf("ingest/fail2ban: fetch banned: %v", err)
		return
	}

	current, err := parseBanned(data)
	if err != nil {
		log.Printf("ingest/fail2ban: parse banned: %v", err)
		return
	}

	// Emit events for newly-banned IPs.
	for ip, jail := range current {
		if _, alreadySeen := seen[ip]; alreadySeen {
			continue
		}
		// Block rather than drop: seen must stay consistent with events emitted.
		select {
		case ch <- proto.Event{
			IP:         ip,
			Reason:     f.resolveReason(jail),
			Timestamp:  time.Now(),
			ReporterID: f.selfID,
		}:
			seen[ip] = struct{}{}
		case <-ctx.Done():
			return
		}
	}

	// Prune IPs that are no longer banned so a re-ban triggers a new event.
	for ip := range seen {
		if _, stillBanned := current[ip]; !stillBanned {
			delete(seen, ip)
		}
	}
}

// resolveReason maps a fail2ban jail name to a SwarmGuard reason string.
// Resolution order: operator config override → exact built-in → prefix built-in → fallback.
func (f *Fail2Ban) resolveReason(jail string) string {
	if r, ok := f.cfg.JailReasons[jail]; ok {
		return r
	}
	if r, ok := builtinJailReasons[jail]; ok {
		return r
	}
	for _, p := range builtinJailPrefixes {
		if strings.HasPrefix(jail, p.prefix) {
			return p.reason
		}
	}
	return "fail2ban-" + jail
}

// parseBanned parses the JSON output of `fail2ban-client banned`.
// Format: [{"jail1": ["ip1", "ip2"]}, {"jail2": ["ip3"]}]
// Returns a map of IP → jail name.
func parseBanned(data []byte) (map[string]string, error) {
	var raw []map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	result := make(map[string]string, len(raw))
	for _, jailMap := range raw {
		for jail, ips := range jailMap {
			for _, ip := range ips {
				result[ip] = jail
			}
		}
	}
	return result, nil
}
