package repquery

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"

	"golang.org/x/sync/singleflight"

	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// maxCacheEntries bounds the per-IP answer cache. Package var so tests can
// shrink it (same precedent as responderStreamTimeout).
var maxCacheEntries = 65536

// Querier fetches reputation from configured aggregators on demand and caches
// the merged answer per IP.
type Querier struct {
	host        host.Host
	aggregators []peer.AddrInfo
	timeout     time.Duration
	cacheTTL    time.Duration

	halfLife           time.Duration
	strangerCap        float64
	federationDiscount float64

	sf singleflight.Group

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	entry store.ScoreRecord
	ok    bool
	at    time.Time
}

// NewQuerier builds a Querier. aggregators is the trusted set to ask; their
// addresses are seeded into the host peerstore so NewStream can dial them
// without an explicit Connect per query. halfLife/strangerCap/federationDiscount
// are the CONSUMER's own reputation parameters, used to recompute each federated
// EvidenceAggregate answer under local rules (§8).
func NewQuerier(h host.Host, aggregators []peer.AddrInfo, timeout, cacheTTL time.Duration, halfLife time.Duration, strangerCap, federationDiscount float64) *Querier {
	if h != nil {
		for _, a := range aggregators {
			h.Peerstore().AddAddrs(a.ID, a.Addrs, peerstore.PermanentAddrTTL)
		}
	}
	return &Querier{
		host: h, aggregators: aggregators, timeout: timeout, cacheTTL: cacheTTL,
		halfLife: halfLife, strangerCap: strangerCap, federationDiscount: federationDiscount,
		cache: map[string]cacheEntry{},
	}
}

// Query returns the merged (max-score) reputation for ip across aggregators,
// each aggregator's EvidenceAggregate recomputed into a ScoreRecord under the
// consumer's own parameters. ok is false if no aggregator returned a
// non-empty record. Cached by IP; a negative result is cached for a fraction
// of the TTL to avoid hammering.
func (q *Querier) Query(ctx context.Context, ip string) (store.ScoreRecord, bool) {
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

	type qres struct {
		entry store.ScoreRecord
		ok    bool
	}
	v, _, _ := q.sf.Do(ip, func() (interface{}, error) {
		merged, ok := q.fanout(ctx, ip)
		q.mu.Lock()
		if len(q.cache) >= maxCacheEntries {
			q.evictLocked(time.Now())
		}
		q.cache[ip] = cacheEntry{entry: merged, ok: ok, at: time.Now()}
		q.mu.Unlock()
		return qres{merged, ok}, nil
	})
	r := v.(qres)
	return r.entry, r.ok
}

// fanout asks every aggregator concurrently within the timeout, recomputes
// each returned EvidenceAggregate into a ScoreRecord under the consumer's own
// parameters, and merges by max recomputed score.
func (q *Querier) fanout(ctx context.Context, ip string) (store.ScoreRecord, bool) {
	qctx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	type res struct {
		ev proto.EvidenceAggregate
		ok bool
	}
	ch := make(chan res, len(q.aggregators))
	for _, agg := range q.aggregators {
		go func(a peer.AddrInfo) {
			ev, ok := q.ask(qctx, a, ip)
			ch <- res{ev, ok}
		}(agg)
	}

	var best store.ScoreRecord
	found := false
	reasons := map[string]bool{}
collect:
	for i := 0; i < len(q.aggregators); i++ {
		select {
		case r := <-ch:
			if !r.ok {
				continue
			}
			rec := RecordFromEvidence(r.ev, time.Now(), q.halfLife, q.strangerCap, q.federationDiscount)
			if rec.LastSeen.IsZero() {
				continue
			}
			for _, rs := range rec.Reasons {
				reasons[rs] = true
			}
			if !found || rec.Score > best.Score {
				best = rec
			}
			found = true
		case <-qctx.Done():
			// Deadline hit: return whatever answered in time rather than
			// blocking on a straggler that may never send.
			break collect
		}
	}
	if found {
		best.Reasons = best.Reasons[:0]
		for rs := range reasons {
			best.Reasons = append(best.Reasons, rs)
		}
	}
	return best, found
}

// ask opens a stream to one aggregator, sends the query, reads the answer.
func (q *Querier) ask(ctx context.Context, a peer.AddrInfo, ip string) (proto.EvidenceAggregate, bool) {
	s, err := q.host.NewStream(ctx, a.ID, ProtocolID)
	if err != nil {
		return proto.EvidenceAggregate{}, false
	}
	defer s.Close()
	// The context bounds dial + protocol negotiation only; set a stream
	// deadline so the encode/decode below cannot block past the query timeout.
	if dl, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(dl)
	}
	if err := json.NewEncoder(s).Encode(proto.RepQuery{IP: ip}); err != nil {
		return proto.EvidenceAggregate{}, false
	}
	var ev proto.EvidenceAggregate
	if err := json.NewDecoder(s).Decode(&ev); err != nil {
		return proto.EvidenceAggregate{}, false
	}
	// Empty answer (WindowLast zero) means the aggregator has no record.
	if ev.WindowLast.IsZero() {
		return proto.EvidenceAggregate{}, false
	}
	return ev, true
}

// evictLocked drops expired entries first, then the single oldest if still at
// capacity. Caller holds q.mu. Negative entries expire at cacheTTL/5, positive
// at cacheTTL (same rule the read path applies).
func (q *Querier) evictLocked(now time.Time) {
	for k, c := range q.cache {
		ttl := q.cacheTTL
		if !c.ok {
			ttl = q.cacheTTL / 5
		}
		if now.Sub(c.at) >= ttl {
			delete(q.cache, k)
		}
	}
	if len(q.cache) < maxCacheEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	first := true
	for k, c := range q.cache {
		if first || c.at.Before(oldest) {
			oldest, oldestKey, first = c.at, k, false
		}
	}
	if oldestKey != "" {
		delete(q.cache, oldestKey)
	}
}
