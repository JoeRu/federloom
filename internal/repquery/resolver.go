package repquery

import (
	"context"

	"github.com/JoeRu/federloom/internal/store"
)

// Resolver answers point reputation lookups: the local store first, then (on a
// miss) the configured aggregators via the querier. It is the single read path
// the DNSBL and the point-lookup score API consume. Read-only.
type Resolver struct {
	local       Store
	q           *Querier                                            // nil = federation disabled
	onFederated func(ip string, rec store.ScoreRecord, subnets int) // nil = no materialise
	shed        func() bool                                         // nil = never shed; true = over budget, skip federated fan-out
}

// NewResolver wraps a local store; q may be nil (federation off); onFederated
// may be nil (no materialise); shed may be nil (never shed). onFederated is
// invoked on a FEDERATED hit only — the resolver never writes; the callback
// owner (the node) decides enforcement.
func NewResolver(local Store, q *Querier, onFederated func(ip string, rec store.ScoreRecord, subnets int), shed func() bool) *Resolver {
	return &Resolver{local: local, q: q, onFederated: onFederated, shed: shed}
}

// SetMaterialiser sets (or replaces) the federated-hit callback.
func (r *Resolver) SetMaterialiser(fn func(ip string, rec store.ScoreRecord, subnets int)) {
	r.onFederated = fn
}

// SetShed sets (or replaces) the load-shedding predicate for the federated
// fan-out. nil (the default) means never shed.
func (r *Resolver) SetShed(fn func() bool) {
	r.shed = fn
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
	if r.shed != nil && r.shed() {
		return rec, nil // over budget → local-only answer (same as the E3 timeout fallback)
	}
	if rec2, subnets, ok := r.q.Query(context.Background(), ip); ok {
		if r.onFederated != nil {
			r.onFederated(ip, rec2, subnets)
		}
		return rec2, nil
	}
	return rec, nil // federated miss → the (empty) local record
}
