package observability

import (
	"strings"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/pkg/proto"
)

func newTestObserver(t *testing.T) *Observer {
	t.Helper()
	cfg := config.ObservabilityConfig{PrometheusAddr: ""}
	repCfg := config.ReputationConfig{BlockThreshold: 75}
	o, err := New(cfg, repCfg, t.TempDir())
	if err != nil {
		t.Fatalf("New observer: %v", err)
	}
	// Observer may be nil when both outputs disabled — create a minimal one for testing
	if o == nil {
		o = &Observer{
			blockedByRule:     make(map[string]string),
			recentlyUnblocked: make(map[string]unblockedEntry),
		}
	}
	return o
}

func TestObserver_RecordBlock_IdempotentGauge(t *testing.T) {
	// Second RecordBlock for same IP must not double-count.
	o := newTestObserver(t)
	first := time.Now().Add(-2 * time.Minute)
	o.RecordBlock("1.2.3.4", "ssh-burst", 80.0, first, 2)
	o.RecordBlock("1.2.3.4", "ssh-burst", 85.0, first, 3) // duplicate

	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.blockedByRule) != 1 {
		t.Errorf("expected 1 entry in blockedByRule, got %d", len(o.blockedByRule))
	}
}

func TestObserver_RecordUnblock_TracksRule(t *testing.T) {
	// RecordUnblock should populate recentlyUnblocked with the rule from RecordBlock.
	o := newTestObserver(t)
	o.RecordBlock("1.2.3.4", "http-probe-consensus", 80.0, time.Now().Add(-1*time.Minute), 2)
	o.RecordUnblock("1.2.3.4")

	o.mu.Lock()
	defer o.mu.Unlock()
	entry, ok := o.recentlyUnblocked["1.2.3.4"]
	if !ok {
		t.Fatal("expected entry in recentlyUnblocked after RecordUnblock")
	}
	if entry.rule != "http-probe-consensus" {
		t.Errorf("rule = %q, want http-probe-consensus", entry.rule)
	}
}

func TestObserver_Recurrence_DetectedOnReblock(t *testing.T) {
	// Block → Unblock → Re-block within 7 days: must add to recentlyUnblocked
	// and RecordBlock must detect the recurrence.
	o := newTestObserver(t)
	first := time.Now().Add(-3 * time.Minute)
	o.RecordBlock("1.2.3.4", "score-fallback", 80.0, first, 1)
	o.RecordUnblock("1.2.3.4")

	// Re-block the same IP (simulates it coming back)
	o.RecordBlock("1.2.3.4", "score-fallback", 90.0, time.Now().Add(-30*time.Second), 2)

	o.mu.Lock()
	defer o.mu.Unlock()
	// After re-block, recentlyUnblocked should be cleared for this IP
	if _, still := o.recentlyUnblocked["1.2.3.4"]; still {
		t.Error("expected recentlyUnblocked to be cleared after re-block")
	}
}

func TestObserver_NilSafe(t *testing.T) {
	var o *Observer
	// All methods must be no-ops on nil receiver.
	e := proto.Event{IP: "1.2.3.4", Reason: "test", ReporterID: "p1"}
	o.RecordEvent(e, 50.0, "rule", "block")
	o.RecordBlock("1.2.3.4", "rule", 80.0, time.Now(), 1)
	o.RecordUnblock("1.2.3.4")
	o.UpdatePeers(3)
	o.RecordFederated("out")
}

func TestObserver_Recurrence_EmitsPrometheusMetric(t *testing.T) {
	// Observer with real prometheusOutput (empty addr uses a custom registry).
	// We need prom to be non-nil to exercise the recordRecurrence path.
	p, err := newPrometheusOutput("", 37.5)
	if err != nil {
		t.Fatal(err)
	}
	o := &Observer{
		prom:              p,
		blockedByRule:     make(map[string]string),
		recentlyUnblocked: make(map[string]unblockedEntry),
	}

	// Block → Unblock → Re-block (within 7 days)
	o.RecordBlock("5.6.7.8", "ssh-burst", 80.0, time.Now().Add(-2*time.Minute), 1)
	o.RecordUnblock("5.6.7.8")
	o.RecordBlock("5.6.7.8", "ssh-burst", 90.0, time.Now().Add(-30*time.Second), 1)

	body := scrape(t, p)
	if !strings.Contains(body, `federloom_block_recurrence_total{rule="ssh-burst"} 1`) {
		t.Errorf("missing block_recurrence_total in:\n%s", body)
	}
}

func TestObserver_RecordUnblock_NeverBlocked_IsNoop(t *testing.T) {
	o := newTestObserver(t)
	// Unblocking an IP that was never blocked must not panic and must not modify state.
	o.RecordUnblock("9.9.9.9")

	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.blockedByRule) != 0 {
		t.Errorf("expected empty blockedByRule, got %d entries", len(o.blockedByRule))
	}
	if len(o.recentlyUnblocked) != 0 {
		t.Errorf("expected empty recentlyUnblocked, got %d entries", len(o.recentlyUnblocked))
	}
}
