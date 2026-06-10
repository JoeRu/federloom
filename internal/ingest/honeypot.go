package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// cowrieEvent is one JSON line from cowrie.json.
type cowrieEvent struct {
	EventID   string `json:"eventid"`
	SrcIP     string `json:"src_ip"`
	Timestamp string `json:"timestamp"`
}

// cowrieReasons maps Cowrie eventid to SwarmGuard reason strings.
var cowrieReasons = map[string]string{
	"cowrie.login.success":   "ssh-auth-success",
	"cowrie.login.failed":    "ssh-auth-bruteforce",
	"cowrie.command.input":   "ssh-post-auth-command",
	"cowrie.session.connect": "ssh-probe",
}

// Honeypot tails a Cowrie JSONL log and emits proto.Events.
// All events carry Trust=1.0 (ground-truth anchor, spec §4.1).
type Honeypot struct {
	cfg    config.HoneypotConfig
	selfID string
}

// Compile-time check: Honeypot must implement Source.
var _ Source = (*Honeypot)(nil)

// NewHoneypot creates a Honeypot adapter. selfID is the local node's peer ID,
// used as ReporterID so peers can track corroboration.
func NewHoneypot(cfg config.HoneypotConfig, selfID string) *Honeypot {
	return &Honeypot{cfg: cfg, selfID: selfID}
}

func (h *Honeypot) Name() string { return "cowrie" }

// Start begins tailing the Cowrie log file and emitting events until ctx is cancelled.
func (h *Honeypot) Start(ctx context.Context) (<-chan proto.Event, error) {
	ch := make(chan proto.Event, 64)
	go h.tail(ctx, ch)
	return ch, nil
}

func (h *Honeypot) tail(ctx context.Context, ch chan<- proto.Event) {
	defer close(ch)

	pollInterval := h.cfg.PollInterval.Duration
	if pollInterval <= 0 {
		pollInterval = time.Second
	}

	var offset int64
	var lastSize int64

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f, err := os.Open(h.cfg.LogFile)
			if err != nil {
				continue // file not yet created — wait
			}

			fi, err := f.Stat()
			if err != nil {
				f.Close()
				continue
			}

			// Log rotation: file shrank — reopen from start.
			if fi.Size() < lastSize {
				offset = 0
			}
			lastSize = fi.Size()

			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				f.Close()
				continue
			}

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Bytes()
				offset += int64(len(line)) + 1 // +1 for newline

				var ce cowrieEvent
				if err := json.Unmarshal(line, &ce); err != nil {
					continue
				}
				if ce.SrcIP == "" {
					continue
				}

				reason, ok := cowrieReasons[ce.EventID]
				if !ok {
					reason = "ssh-unknown"
				}

				e := proto.Event{
					IP:         ce.SrcIP,
					Reason:     reason,
					Timestamp:  time.Now(),
					ReporterID: h.selfID,
				}

				select {
				case ch <- e:
				case <-ctx.Done():
					f.Close()
					return
				default:
					// Channel full — drop (high-volume honeypot noise).
					log.Printf("ingest/cowrie: channel full, dropping event for %s", ce.SrcIP)
				}
			}
			f.Close()
		}
	}
}
