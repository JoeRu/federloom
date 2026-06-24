package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/pkg/proto"
)

// openCanaryEvent is one JSON line from OpenCanary's log.
type openCanaryEvent struct {
	SrcHost   string `json:"src_host"`
	LogType   int    `json:"logtype"`
	LocalTime string `json:"local_time"`
}

// openCanaryReasons maps OpenCanary logtype to FederLoom reason strings.
// Verified against /opencanary/opencanary/logger.py in the running container.
// Cross-check: docker exec opencanary cat /opencanary/opencanary/logger.py | grep LOG_
//
// HTTP and HTTPS share the same logtypes — CanaryHTTPS reuses CanaryHTTP handlers;
// the destination port (80 vs 443) distinguishes the protocol in the raw log event.
var openCanaryReasons = map[int]string{
	2000: "ftp-login-attempt",
	2001: "ftp-auth-attempt",
	3000: "http-probe",            // LOG_HTTP_GET — fires for both HTTP and HTTPS GET
	3001: "http-post-login",       // LOG_HTTP_POST_LOGIN_ATTEMPT
	3002: "http-unimplemented",    // LOG_HTTP_UNIMPLEMENTED_METHOD
	3003: "http-redirect",         // LOG_HTTP_REDIRECT
	4000: "ssh-new-connection",    // LOG_SSH_NEW_CONNECTION
	4001: "ssh-remote-version",    // LOG_SSH_REMOTE_VERSION_SENT
	4002: "ssh-login-attempt",     // LOG_SSH_LOGIN_ATTEMPT
	5000: "smb-file-open",         // LOG_SMB_FILE_OPEN
	6001: "telnet-login-attempt",  // LOG_TELNET_LOGIN_ATTEMPT
	7001: "http-proxy-login",      // LOG_HTTPPROXY_LOGIN_ATTEMPT
	8001: "mysql-login-attempt",   // LOG_MYSQL_LOGIN_ATTEMPT
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
			scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MiB cap — avoids silent truncation
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
			if err := scanner.Err(); err != nil {
				log.Printf("ingest/opencanary: scan error on %s: %v", o.cfg.LogFile, err)
			}
			f.Close()
		}
	}
}
