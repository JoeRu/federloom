package ingest_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/ingest"
	"github.com/JoeRu/federloom/pkg/proto"
)

// rotationCase describes one file-tailing source for the rename-rotation test.
type rotationCase struct {
	name  string
	start func(path string, ctx context.Context) (<-chan proto.Event, error)
	line  func(ip string) string
}

var rotationCases = []rotationCase{
	{
		name: "cowrie",
		start: func(path string, ctx context.Context) (<-chan proto.Event, error) {
			return ingest.NewHoneypot(config.HoneypotConfig{Enabled: true, LogFile: path,
				PollInterval: config.Duration{Duration: 20 * time.Millisecond}}, "selfpeer").Start(ctx)
		},
		line: func(ip string) string {
			return fmt.Sprintf(`{"eventid":"cowrie.login.failed","src_ip":"%s"}`, ip)
		},
	},
	{
		name: "opencanary",
		start: func(path string, ctx context.Context) (<-chan proto.Event, error) {
			return ingest.NewOpenCanary(config.OpenCanaryConfig{Enabled: true, LogFile: path,
				PollInterval: config.Duration{Duration: 20 * time.Millisecond}}, "selfpeer").Start(ctx)
		},
		line: func(ip string) string { return fmt.Sprintf(`{"src_host":"%s","logtype":3000}`, ip) },
	},
	{
		name: "spamtrap",
		start: func(path string, ctx context.Context) (<-chan proto.Event, error) {
			return ingest.NewSpamtrap(config.SpamtrapConfig{Enabled: true, LogFile: path,
				PollInterval: config.Duration{Duration: 20 * time.Millisecond}}, "selfpeer").Start(ctx)
		},
		line: func(ip string) string { return ip },
	},
}

// TestRenameRotationToLargerFileIsReadFromStart covers rename-style rotation
// where the replacement file is already larger than the old one by the next
// poll. Size-based detection alone misses that case and resumes at the old
// offset, silently skipping the new file's prefix; the tailers must notice the
// file identity changed and start over.
func TestRenameRotationToLargerFileIsReadFromStart(t *testing.T) {
	for _, tc := range rotationCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "source.log")
			writeLines(t, path, []string{tc.line("198.51.100.1")})

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ch, err := tc.start(path, ctx)
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			if e := recvEvent(t, ctx, ch); e.IP != "198.51.100.1" {
				t.Fatalf("first event IP = %q, want 198.51.100.1", e.IP)
			}

			// Rotate: rename the old file away and write a new, larger one at the
			// same path before the tailer polls again.
			if err := os.Rename(path, path+".1"); err != nil {
				t.Fatalf("rename: %v", err)
			}
			newLines := make([]string, 20)
			for i := range newLines {
				newLines[i] = tc.line(fmt.Sprintf("203.0.113.%d", i+1))
			}
			// Write the replacement elsewhere and move it into place atomically, so
			// the tailer never sees a partially written (smaller) file.
			tmp := filepath.Join(dir, "next.tmp")
			writeLines(t, tmp, newLines)
			if err := os.Rename(tmp, path); err != nil {
				t.Fatalf("rename replacement: %v", err)
			}

			for i := range newLines {
				want := fmt.Sprintf("203.0.113.%d", i+1)
				if e := recvEvent(t, ctx, ch); e.IP != want {
					t.Fatalf("event %d after rotation: IP = %q, want %q (prefix of the new file was skipped)", i, e.IP, want)
				}
			}
		})
	}
}

func recvEvent(t *testing.T, ctx context.Context, ch <-chan proto.Event) proto.Event {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
	return proto.Event{}
}
