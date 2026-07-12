package repquery

import (
	"context"

	"github.com/JoeRu/federloom/internal/store"
)

// Resolver answers point reputation lookups: the local store first, then (on a
// miss) the configured aggregators via the querier. It is the single read path
// the DNSBL and the point-lookup score API consume. Read-only.
type Resolver struct {
	local Store
	q     *Querier // nil = federation disabled
}

// NewResolver wraps a local store; q may be nil (federation off).
func NewResolver(local Store, q *Querier) *Resolver {
	return &Resolver{local: local, q: q}
}

// GetScore returns the local record if present, else a federated answer
// recomputed from evidence, else an empty record. Never errors on the
// federated path — a miss/timeout degrades to the local (empty) answer.
func (r *Resolver) GetScore(ip string) (store.ScoreRecord, error) {
	rec, err := r.local.GetScore(ip)
	if err != nil {
		return rec, err
	}
	if !rec.LastSeen.IsZero() || r.q == nil {
		return rec, nil // local hit, or federation disabled
	}
	if rec2, ok := r.q.Query(context.Background(), ip); ok {
		return rec2, nil
	}
	return rec, nil // federated miss → the (empty) local record
}
