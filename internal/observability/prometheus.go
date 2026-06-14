package observability

import (
	"context"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

type prometheusOutput struct {
	events     *prometheus.CounterVec
	rules      *prometheus.CounterVec
	blockedIPs prometheus.Gauge
	score      *prometheus.GaugeVec
	peers      prometheus.Gauge
	federated  *prometheus.CounterVec
	registry   *prometheus.Registry
	threshold  float64
	addr       string
}

func newPrometheusOutput(addr string, scoreThreshold float64) (*prometheusOutput, error) {
	reg := prometheus.NewRegistry()
	p := &prometheusOutput{
		addr:      addr,
		threshold: scoreThreshold,
		registry:  reg,
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "swarmguard_events_received_total",
			Help: "Total events processed by the reputation engine.",
		}, []string{"reason", "reporter_id"}),
		rules: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "swarmguard_rules_fired_total",
			Help: "Total rule evaluations that produced a match.",
		}, []string{"rule", "action"}),
		blockedIPs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "swarmguard_blocked_ips",
			Help: "Current number of IPs in the enforced block set.",
		}),
		score: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "swarmguard_ip_score",
			Help: "Current reputation score for IPs at or above the gauge threshold.",
		}, []string{"ip"}),
		peers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "swarmguard_federation_peers",
			Help: "Number of connected libp2p peers.",
		}),
		federated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "swarmguard_events_federated_total",
			Help: "Gossip messages exchanged with peers.",
		}, []string{"direction"}),
	}
	for _, c := range []prometheus.Collector{
		p.events, p.rules, p.blockedIPs, p.score, p.peers, p.federated,
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
