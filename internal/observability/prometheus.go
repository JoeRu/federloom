package observability

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/JoeRu/federloom/pkg/proto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type prometheusOutput struct {
	events        *prometheus.CounterVec
	rules         *prometheus.CounterVec
	blockedIPs    prometheus.Gauge
	score         *prometheus.GaugeVec
	peers         prometheus.Gauge
	federated     *prometheus.CounterVec
	blocks        *prometheus.CounterVec
	timeToBlock   *prometheus.HistogramVec
	corroboration *prometheus.HistogramVec
	unblocks      *prometheus.CounterVec
	recurrences   *prometheus.CounterVec
	registry      *prometheus.Registry
	threshold     float64
	addr          string
}

func newPrometheusOutput(addr string, scoreThreshold float64) (*prometheusOutput, error) {
	reg := prometheus.NewRegistry()
	p := &prometheusOutput{
		addr:      addr,
		threshold: scoreThreshold,
		registry:  reg,
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "federloom_events_received_total",
			Help: "Total events processed by the reputation engine.",
		}, []string{"reason", "reporter_id"}),
		rules: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "federloom_rules_fired_total",
			Help: "Total rule evaluations that produced a match.",
		}, []string{"rule", "action"}),
		blockedIPs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "federloom_blocked_ips",
			Help: "Current number of IPs in the enforced block set.",
		}),
		score: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "federloom_ip_score",
			Help: "Current reputation score for IPs at or above the gauge threshold.",
		}, []string{"ip"}),
		peers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "federloom_federation_peers",
			Help: "Number of connected libp2p peers.",
		}),
		federated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "federloom_events_federated_total",
			Help: "Gossip messages exchanged with peers.",
		}, []string{"direction"}),
		blocks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "federloom_blocks_total",
			Help: "Total IPs moved into the block set, by rule.",
		}, []string{"rule"}),
		timeToBlock: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "federloom_time_to_block_seconds",
			Help:    "Duration from first event to block decision, by rule.",
			Buckets: []float64{0, 30, 60, 120, 300, 600, 1800, 3600, 14400},
		}, []string{"rule"}),
		corroboration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "federloom_corroboration_at_block",
			Help:    "Number of distinct reporters at block time, by rule.",
			Buckets: []float64{1, 2, 3, 4, 5, 10},
		}, []string{"rule"}),
		unblocks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "federloom_unblocks_total",
			Help: "Total IPs removed from the block set by score decay, by rule.",
		}, []string{"rule"}),
		recurrences: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "federloom_block_recurrence_total",
			Help: "Previously-unblocked IPs re-blocked within 7 days, by original rule.",
		}, []string{"rule"}),
	}
	for _, c := range []prometheus.Collector{
		p.events, p.rules, p.blockedIPs, p.score, p.peers, p.federated,
		p.blocks, p.timeToBlock, p.corroboration, p.unblocks, p.recurrences,
	} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *prometheusOutput) start(ctx context.Context) {
	if p.addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: p.addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("observability: prometheus: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
}

func (p *prometheusOutput) recordEvent(e proto.Event, score float64, rule, action string) {
	p.events.WithLabelValues(e.Reason, e.ReporterID).Inc()
	if rule != "" {
		p.rules.WithLabelValues(rule, action).Inc()
	}
	if score >= p.threshold {
		p.score.WithLabelValues(e.IP).Set(score)
	} else {
		p.score.DeleteLabelValues(e.IP)
	}
}

func (p *prometheusOutput) recordBlock(rule string, firstSeen time.Time, corroboration int) {
	p.blocks.WithLabelValues(rule).Inc()
	p.timeToBlock.WithLabelValues(rule).Observe(time.Since(firstSeen).Seconds())
	p.corroboration.WithLabelValues(rule).Observe(float64(corroboration))
}

func (p *prometheusOutput) recordUnblock(rule string) {
	p.unblocks.WithLabelValues(rule).Inc()
}

func (p *prometheusOutput) recordRecurrence(rule string) {
	p.recurrences.WithLabelValues(rule).Inc()
}
