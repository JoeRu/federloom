package observability

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/pkg/proto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func scrape(t *testing.T, p *prometheusOutput) string {
	t.Helper()
	w := httptest.NewRecorder()
	promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{}).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(w.Body)
	return string(body)
}

func TestPrometheusOutput_RecordEvent_Counter(t *testing.T) {
	p, err := newPrometheusOutput("", 37.5)
	if err != nil {
		t.Fatalf("newPrometheusOutput: %v", err)
	}
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1"}
	p.recordEvent(e, 50.0, "my-rule", "block")

	body := scrape(t, p)
	if !strings.Contains(body, `swarmguard_events_received_total{reason="ssh-probe",reporter_id="peer1"} 1`) {
		t.Errorf("missing events counter in:\n%s", body)
	}
	if !strings.Contains(body, `swarmguard_rules_fired_total{action="block",rule="my-rule"} 1`) {
		t.Errorf("missing rules counter in:\n%s", body)
	}
}

func TestPrometheusOutput_ScoreGauge_AboveThreshold(t *testing.T) {
	p, _ := newPrometheusOutput("", 40.0)
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1"}
	p.recordEvent(e, 50.0, "", "")

	body := scrape(t, p)
	if !strings.Contains(body, `swarmguard_ip_score{ip="1.2.3.4"} 50`) {
		t.Errorf("expected ip_score gauge above threshold in:\n%s", body)
	}
}

func TestPrometheusOutput_ScoreGauge_BelowThreshold(t *testing.T) {
	p, _ := newPrometheusOutput("", 40.0)
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1"}
	p.recordEvent(e, 30.0, "", "") // below threshold

	body := scrape(t, p)
	if strings.Contains(body, `swarmguard_ip_score{ip="1.2.3.4"}`) {
		t.Errorf("ip_score should not appear below threshold in:\n%s", body)
	}
}

func TestPrometheusOutput_BlockedGauge(t *testing.T) {
	p, _ := newPrometheusOutput("", 37.5)
	p.blockedIPs.Inc()
	p.blockedIPs.Inc()
	p.blockedIPs.Dec()

	body := scrape(t, p)
	if !strings.Contains(body, "swarmguard_blocked_ips 1") {
		t.Errorf("expected blocked_ips=1 in:\n%s", body)
	}
}

func TestPrometheusOutput_NoRuleName_SkipsRuleCounter(t *testing.T) {
	p, _ := newPrometheusOutput("", 37.5)
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1"}
	p.recordEvent(e, 50.0, "", "") // no rule matched

	body := scrape(t, p)
	if strings.Contains(body, "swarmguard_rules_fired_total") {
		t.Errorf("rules counter should not appear when no rule matched in:\n%s", body)
	}
}

func TestPrometheusOutput_RecordBlock_EmitsCounterAndHistograms(t *testing.T) {
	p, _ := newPrometheusOutput("", 37.5)
	firstSeen := time.Now().Add(-5 * time.Minute)
	p.recordBlock("ssh-burst", firstSeen, 3)

	body := scrape(t, p)
	if !strings.Contains(body, `swarmguard_blocks_total{rule="ssh-burst"} 1`) {
		t.Errorf("missing blocks_total in:\n%s", body)
	}
	if !strings.Contains(body, `swarmguard_time_to_block_seconds_count{rule="ssh-burst"} 1`) {
		t.Errorf("missing time_to_block histogram in:\n%s", body)
	}
	if !strings.Contains(body, `swarmguard_corroboration_at_block_count{rule="ssh-burst"} 1`) {
		t.Errorf("missing corroboration histogram in:\n%s", body)
	}
}

func TestPrometheusOutput_RecordUnblock_EmitsCounter(t *testing.T) {
	p, _ := newPrometheusOutput("", 37.5)
	p.recordUnblock("http-probe-consensus")

	body := scrape(t, p)
	if !strings.Contains(body, `swarmguard_unblocks_total{rule="http-probe-consensus"} 1`) {
		t.Errorf("missing unblocks_total in:\n%s", body)
	}
}

func TestPrometheusOutput_RecordRecurrence_EmitsCounter(t *testing.T) {
	p, _ := newPrometheusOutput("", 37.5)
	p.recordRecurrence("score-fallback")

	body := scrape(t, p)
	if !strings.Contains(body, `swarmguard_block_recurrence_total{rule="score-fallback"} 1`) {
		t.Errorf("missing block_recurrence_total in:\n%s", body)
	}
}
