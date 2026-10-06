package ingest_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/ingest"
	"github.com/JoeRu/federloom/pkg/proto"
)

// burst is larger than any adapter's channel buffer (64), so a source that
// drops on a full channel loses events while nobody reads.
const burst = 300

// drainAfter waits until the source has had time to read the whole burst and
// hit a full channel, then counts what arrives. A source that applies
// backpressure delivers all of them; one that drops on a full buffer does not.
func drainAfter(t *testing.T, ctx context.Context, ch <-chan proto.Event, want int) {
	t.Helper()
	time.Sleep(500 * time.Millisecond) // several poll intervals with no reader
	got := 0
	for got < want {
		select {
		case <-ch:
			got++
		case <-ctx.Done():
			t.Fatalf("received %d of %d events: events were dropped under burst", got, want)
		}
	}
}

func TestHoneypotBurstIsNotDropped(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "cowrie.json")
	lines := make([]string, burst)
	for i := range lines {
		lines[i] = fmt.Sprintf(`{"eventid":"cowrie.login.failed","src_ip":"198.51.100.%d"}`, i%250+1)
	}
	writeLines(t, logPath, lines)

	h := ingest.NewHoneypot(config.HoneypotConfig{
		Enabled: true, LogFile: logPath,
		PollInterval: config.Duration{Duration: 20 * time.Millisecond},
	}, "selfpeer")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := h.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	drainAfter(t, ctx, ch, burst)
}

func TestOpenCanaryBurstIsNotDropped(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "opencanary.log")
	lines := make([]string, burst)
	for i := range lines {
		lines[i] = fmt.Sprintf(`{"src_host":"198.51.100.%d","logtype":3000}`, i%250+1)
	}
	writeLines(t, logPath, lines)

	o := ingest.NewOpenCanary(config.OpenCanaryConfig{
		Enabled: true, LogFile: logPath,
		PollInterval: config.Duration{Duration: 20 * time.Millisecond},
	}, "selfpeer")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := o.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	drainAfter(t, ctx, ch, burst)
}

func TestSpamtrapBurstIsNotDropped(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "spamtrap.txt")
	lines := make([]string, burst)
	for i := range lines {
		lines[i] = fmt.Sprintf("198.51.100.%d", i%250+1)
	}
	writeLines(t, logPath, lines)

	s := ingest.NewSpamtrap(config.SpamtrapConfig{
		Enabled: true, LogFile: logPath,
		PollInterval: config.Duration{Duration: 20 * time.Millisecond},
	}, "selfpeer")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	drainAfter(t, ctx, ch, burst)
}

func TestMailcowBurstIsNotDropped(t *testing.T) {
	var postfixCalls atomic.Int32
	m := makeMailcow(t, func(container string) []byte {
		// Only the first postfix poll returns the burst; later polls are empty,
		// so the count is exact.
		if container != "test-postfix" || postfixCalls.Add(1) > 1 {
			return nil
		}
		var b []byte
		for i := 0; i < burst; i++ {
			b = append(b, fmt.Sprintf("Jun 17 10:12:34 mx postfix/smtpd[123]: warning: unknown[198.51.100.%d]: SASL LOGIN authentication failed: authentication failure\n", i%250+1)...)
		}
		return b
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	drainAfter(t, ctx, ch, burst)
}
