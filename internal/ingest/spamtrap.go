package ingest

import (
	"bufio"
	"context"
	"io"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/pkg/proto"
)

// Spamtrap tails a log file written by the operator when a never-used mailbox
// receives a delivery attempt. One IPv4 address per line; lines starting with
// "#" and blank lines are ignored.
type Spamtrap struct {
	cfg    config.SpamtrapConfig
	selfID string
}

// Compile-time check.
var _ Source = (*Spamtrap)(nil)

// NewSpamtrap creates a Spamtrap adapter.
func NewSpamtrap(cfg config.SpamtrapConfig, selfID string) *Spamtrap {
	return &Spamtrap{cfg: cfg, selfID: selfID}
}

func (s *Spamtrap) Name() string { return "spamtrap" }

// Start begins tailing the spamtrap log file and emitting events until ctx is cancelled.
func (s *Spamtrap) Start(ctx context.Context) (<-chan proto.Event, error) {
	ch := make(chan proto.Event, 64)
	go s.tail(ctx, ch)
	return ch, nil
}

func (s *Spamtrap) tail(ctx context.Context, ch chan<- proto.Event) {
	defer close(ch)

	pollInterval := s.cfg.PollInterval.Duration
	if pollInterval <= 0 {
		pollInterval = time.Second
	}

	var pos tailPos

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f, err := os.Open(s.cfg.LogFile)
			if err != nil {
				continue // file not yet created — wait
			}

			fi, err := f.Stat()
			if err != nil {
				f.Close()
				continue
			}

			// Log rotation (truncated or replaced file) — read from start.
			pos.sync(fi)

			if _, err := f.Seek(pos.offset, io.SeekStart); err != nil {
				f.Close()
				continue
			}

			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 1<<20), 1<<20)
			for scanner.Scan() {
				raw := scanner.Bytes()
				pos.offset += int64(len(raw)) + 1 // +1 for newline

				line := strings.TrimSpace(string(raw))
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				addr, err := netip.ParseAddr(line)
				if err != nil || !addr.Is4() {
					log.Printf("ingest/spamtrap: invalid IPv4 %q in %s — skipping", line, s.cfg.LogFile)
					continue
				}

				// Block rather than drop when the channel is full: the source is a file,
				// so waiting only delays ingest. Dropping lost the duplicate events of a
				// burst and logged one line per drop; local protection is never shed
				// (spec §11.5).
				select {
				case ch <- proto.Event{IP: line, Reason: "smtp-spamtrap", Timestamp: time.Now(), ReporterID: s.selfID}:
				case <-ctx.Done():
					f.Close()
					return
				}
			}
			if err := scanner.Err(); err != nil {
				log.Printf("ingest/spamtrap: scan error on %s: %v", s.cfg.LogFile, err)
			}
			f.Close()
		}
	}
}
