package observability

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/pkg/proto"
)

type unblockedEntry struct {
	rule        string
	unblockedAt time.Time
}

// Observer fans out observability events to an optional Prometheus output
// and an optional SQLite output. All methods are safe to call on a nil
// *Observer — nil means observability is disabled.
type Observer struct {
	prom              *prometheusOutput
	sq                *sqliteOutput
	mu                sync.Mutex
	blockedByRule     map[string]string         // ip → rule that caused the block
	recentlyUnblocked map[string]unblockedEntry // ip → rule+time; pruned after 7 days
}

// New creates an Observer from cfg. Both outputs are optional; an empty addr
// or path disables that output. Returns nil (not an error) when both are disabled.
func New(cfg config.ObservabilityConfig, repCfg config.ReputationConfig, storeDir string) (*Observer, error) {
	if cfg.PrometheusAddr == "" && cfg.SQLitePath == "" {
		return nil, nil
	}
	o := &Observer{
		blockedByRule:     make(map[string]string),
		recentlyUnblocked: make(map[string]unblockedEntry),
	}

	if cfg.PrometheusAddr != "" {
		threshold := cfg.ScoreGaugeThreshold
		if threshold == 0 {
			threshold = repCfg.BlockThreshold / 2
		}
		p, err := newPrometheusOutput(cfg.PrometheusAddr, threshold)
		if err != nil {
			return nil, err
		}
		o.prom = p
	}

	if cfg.SQLitePath != "" {
		path := cfg.SQLitePath
		if !filepath.IsAbs(path) {
			path = filepath.Join(storeDir, path)
		}
		retention := cfg.SQLiteRetention.Duration
		if retention <= 0 {
			retention = 360 * time.Hour
		}
		halfLife := repCfg.HalfLife.Duration
		if halfLife <= 0 {
			halfLife = 7 * 24 * time.Hour
		}
		sq, err := newSQLiteOutput(path, retention, halfLife, repCfg.BlockThreshold)
		if err != nil {
			return nil, err
		}
		o.sq = sq
	}

	return o, nil
}

// Start launches the Prometheus HTTP server and the SQLite retention sweep goroutine.
func (o *Observer) Start(ctx context.Context) {
	if o == nil {
		return
	}
	if o.prom != nil {
		o.prom.start(ctx)
	}
	if o.sq != nil {
		o.sq.startRetentionSweep(ctx)
	}
}

// RecordEvent records a processed ingest event. rule is empty when no rule matched.
func (o *Observer) RecordEvent(e proto.Event, score float64, rule, action string) {
	if o == nil {
		return
	}
	if o.prom != nil {
		o.prom.recordEvent(e, score, rule, action)
	}
	if o.sq != nil {
		o.sq.recordEvent(e, score)
		if rule != "" {
			o.sq.recordRuleFiring(e, score, rule, action)
		}
	}
}

// RecordBlock records that ip was added to the block set.
// rule is the rule name that triggered the block.
// firstSeen is when the IP was first observed (used to compute time-to-block latency).
// corroboration is the number of distinct reporters at block time.
// Duplicate calls for the same IP are ignored so the gauge stays accurate.
func (o *Observer) RecordBlock(ip, rule string, score float64, firstSeen time.Time, corroboration int) {
	if o == nil {
		return
	}
	o.mu.Lock()
	_, already := o.blockedByRule[ip]
	if !already {
		o.blockedByRule[ip] = rule
	}
	prev, wasUnblocked := o.recentlyUnblocked[ip]
	if wasUnblocked {
		delete(o.recentlyUnblocked, ip)
	}
	o.mu.Unlock()

	if !already {
		if o.prom != nil {
			o.prom.blockedIPs.Inc()
			o.prom.recordBlock(rule, firstSeen, corroboration)
		}
		if o.sq != nil {
			o.sq.recordBlock(ip, score)
		}
	}
	if wasUnblocked && time.Since(prev.unblockedAt) < 7*24*time.Hour {
		if o.prom != nil {
			o.prom.recordRecurrence(prev.rule)
		}
	}
}

// RecordUnblock records that ip was removed from the block set.
func (o *Observer) RecordUnblock(ip string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	rule, was := o.blockedByRule[ip]
	if was {
		delete(o.blockedByRule, ip)
		o.recentlyUnblocked[ip] = unblockedEntry{rule: rule, unblockedAt: time.Now()}
		// Prune entries older than 7 days to prevent unbounded map growth.
		for k, v := range o.recentlyUnblocked {
			if time.Since(v.unblockedAt) > 7*24*time.Hour {
				delete(o.recentlyUnblocked, k)
			}
		}
	}
	o.mu.Unlock()

	if was {
		if o.prom != nil {
			o.prom.blockedIPs.Dec()
			o.prom.recordUnblock(rule)
		}
	}
	if o.sq != nil {
		o.sq.recordUnblock(ip)
	}
}

// UpdatePeers sets the current count of connected libp2p peers.
func (o *Observer) UpdatePeers(n int) {
	if o == nil || o.prom == nil {
		return
	}
	o.prom.peers.Set(float64(n))
}

// RecordFederated increments the gossip message counter. direction is "in" or "out".
func (o *Observer) RecordFederated(direction string) {
	if o == nil || o.prom == nil {
		return
	}
	o.prom.federated.WithLabelValues(direction).Inc()
}
