package repquery

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/pkg/proto"
)

// Querier fetches reputation from configured aggregators on demand and caches
// the merged answer per IP.
type Querier struct {
	host        host.Host
	aggregators []peer.AddrInfo
	timeout     time.Duration
	cacheTTL    time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	entry proto.ScoreEntry
	ok    bool
	at    time.Time
}

// NewQuerier builds a Querier. aggregators is the trusted set to ask.
func NewQuerier(h host.Host, aggregators []peer.AddrInfo, timeout, cacheTTL time.Duration) *Querier {
	return &Querier{host: h, aggregators: aggregators, timeout: timeout, cacheTTL: cacheTTL, cache: map[string]cacheEntry{}}
}

// Query returns the merged (max-score) reputation for ip across aggregators.
// ok is false if no aggregator returned a non-empty record. Cached by IP; a
// negative result is cached for a fraction of the TTL to avoid hammering.
func (q *Querier) Query(ctx context.Context, ip string) (proto.ScoreEntry, bool) {
	now := time.Now()
	q.mu.Lock()
	if c, hit := q.cache[ip]; hit {
		ttl := q.cacheTTL
		if !c.ok {
			ttl = q.cacheTTL / 5 // shorter negative TTL
		}
		if now.Sub(c.at) < ttl {
			q.mu.Unlock()
			return c.entry, c.ok
		}
	}
	q.mu.Unlock()

	merged, ok := q.fanout(ctx, ip)

	q.mu.Lock()
	q.cache[ip] = cacheEntry{entry: merged, ok: ok, at: now}
	q.mu.Unlock()
	return merged, ok
}

// fanout asks every aggregator concurrently within the timeout and merges by max score.
func (q *Querier) fanout(ctx context.Context, ip string) (proto.ScoreEntry, bool) {
	qctx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	type res struct {
		e  proto.ScoreEntry
		ok bool
	}
	ch := make(chan res, len(q.aggregators))
	for _, agg := range q.aggregators {
		go func(a peer.AddrInfo) {
			e, ok := q.ask(qctx, a, ip)
			ch <- res{e, ok}
		}(agg)
	}

	var merged proto.ScoreEntry
	merged.IP = ip
	found := false
	reasons := map[string]bool{}
	for range q.aggregators {
		r := <-ch
		if !r.ok {
			continue
		}
		found = true
		if r.e.Score > merged.Score {
			merged.Score = r.e.Score
			merged.Corroboration = r.e.Corroboration
			merged.FirstSeen = r.e.FirstSeen
			merged.LastSeen = r.e.LastSeen
		}
		for _, rs := range r.e.Reasons {
			reasons[rs] = true
		}
	}
	for rs := range reasons {
		merged.Reasons = append(merged.Reasons, rs)
	}
	return merged, found
}

// ask opens a stream to one aggregator, sends the query, reads the answer.
func (q *Querier) ask(ctx context.Context, a peer.AddrInfo, ip string) (proto.ScoreEntry, bool) {
	if q.host.Network().Connectedness(a.ID) != network.Connected {
		_ = q.host.Connect(ctx, a)
	}
	s, err := q.host.NewStream(ctx, a.ID, ProtocolID)
	if err != nil {
		return proto.ScoreEntry{}, false
	}
	defer s.Close()
	if err := json.NewEncoder(s).Encode(proto.RepQuery{IP: ip}); err != nil {
		return proto.ScoreEntry{}, false
	}
	var e proto.ScoreEntry
	if err := json.NewDecoder(s).Decode(&e); err != nil {
		return proto.ScoreEntry{}, false
	}
	// Empty answer (LastSeen zero) means the aggregator has no record.
	if e.LastSeen.IsZero() {
		return proto.ScoreEntry{}, false
	}
	return e, true
}
