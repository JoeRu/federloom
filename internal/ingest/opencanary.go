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

// openCanaryEvent is one JSON line from OpenCanary's log.
type openCanaryEvent struct {
	SrcHost   string `json:"src_host"`
	LogType   int    `json:"logtype"`
	LocalTime string `json:"local_time"`
}

// openCanaryReasons maps OpenCanary logtype to SwarmGuard reason strings.
// Verify these values against the running OpenCanary version if logtypes change:
//
//	docker exec opencanary grep -r "logtype" /usr/local/lib/python*/dist-packages/opencanary/modules/
var openCanaryReasons = map[int]string{
	3000: "smtp-probe",
	3001: "smtp-auth-bruteforce",
	2100: "imap-probe",
	2101: "imap-auth-bruteforce",
}

// OpenCanary tails an OpenCanary JSONL log and emits proto.Events.
// All events carry Trust=1.0 (ground-truth anchor, spec §4.1).
type OpenCanary struct {
	cfg    config.OpenCanaryConfig
	selfID string
}

// Compile-time check: OpenCanary must implement Source.
var _ Source = (*OpenCanary)(nil)

// NewOpenCanary creates an OpenCanary adapter. selfID is the local node's peer ID.
func NewOpenCanary(cfg config.OpenCanaryConfig, selfID string) *OpenCanary {
	return &OpenCanary{cfg: cfg, selfID: selfID}
}

func (o *OpenCanary) Name() string { return "opencanary" }

// Start begins tailing the OpenCanary log file and emitting events until ctx is cancelled.
func (o *OpenCanary) Start(ctx context.Context) (<-chan proto.Event, error) {
	ch := make(chan proto.Event, 64)
	go o.tail(ctx, ch)
	return ch, nil
}

func (o *OpenCanary) tail(ctx context.Context, ch chan<- proto.Event) {
	defer close(ch)

	pollInterval := o.cfg.PollInterval.Duration
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
			f, err := os.Open(o.cfg.LogFile)
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

				var oe openCanaryEvent
				if err := json.Unmarshal(line, &oe); err != nil {
					continue
				}
				if oe.SrcHost == "" {
					continue
				}

				reason, ok := openCanaryReasons[oe.LogType]
				if !ok {
					reason = "opencanary-unknown"
				}

				e := proto.Event{
					IP:         oe.SrcHost,
					Reason:     reason,
					Timestamp:  time.Now(),
					ReporterID: o.selfID,
				}

				select {
				case ch <- e:
				case <-ctx.Done():
					f.Close()
					return
				default:
					// Channel full — drop (high-volume honeypot noise).
					log.Printf("ingest/opencanary: channel full, dropping event for %s", oe.SrcHost)
				}
			}
			f.Close()
		}
	}
}
