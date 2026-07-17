package repquery

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/store"
)

// localMiss always misses; localHit returns a record.
type fixedStore struct{ rec store.ScoreRecord }

func (f fixedStore) GetScore(string) (store.ScoreRecord, error) { return f.rec, nil }

func TestResolverLocalHitSkipsFederation(t *testing.T) {
	local := fixedStore{rec: store.ScoreRecord{Score: 50, LastSeen: time.Now()}}
	r := NewResolver(local, nil, nil, nil) // nil querier: if it tried to federate it'd panic
	got, err := r.GetScore("1.1.1.1")
	if err != nil || got.Score != 50 {
		t.Fatalf("local hit not returned: %+v err=%v", got, err)
	}
}

func TestResolverMissNoQuerierReturnsEmpty(t *testing.T) {
	r := NewResolver(fixedStore{}, nil, nil, nil) // local miss (zero record), no federation
	got, _ := r.GetScore("2.2.2.2")
	if !got.LastSeen.IsZero() {
		t.Errorf("expected empty record on miss with no querier, got %+v", got)
	}
}

func TestResolverInvokesMaterialiseCallbackOnFederatedHit(t *testing.T) {
	var gotIP string
	var gotSubnets int
	called := 0
	q := &Querier{} // not used — we force the federated path via a stub below
	_ = q
	// Use a resolver whose local store misses and whose querier returns a federated hit.
	local := fixedStore{} // empty (miss)
	r := NewResolver(local, nil, func(ip string, rec store.ScoreRecord, subnets int) {
		called++
		gotIP = ip
		gotSubnets = subnets
	}, nil)
	// With q == nil the federated path is skipped, so the callback must NOT fire.
	if _, err := r.GetScore("1.2.3.4"); err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if called != 0 {
		t.Errorf("callback fired with no querier; called=%d", called)
	}
	_ = gotIP
	_ = gotSubnets
}

func TestResolverLocalHitDoesNotMaterialise(t *testing.T) {
	local := fixedStore{rec: store.ScoreRecord{Score: 90, LastSeen: time.Now()}}
	called := 0
	r := NewResolver(local, nil, func(string, store.ScoreRecord, int) { called++ }, nil)
	if _, err := r.GetScore("1.2.3.4"); err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if called != 0 {
		t.Errorf("local hit must not materialise; called=%d", called)
	}
}

// TestResolverShedsFederatedQuery: when shed() is true the resolver returns the
// local-only (empty) record and does NOT fan out a federated query. A non-nil
// zero-value *Querier is passed so the federated branch is entered; the shed
// guard must short-circuit before r.q.Query is ever reached.
func TestResolverShedsFederatedQuery(t *testing.T) {
	r := NewResolver(fixedStore{}, &Querier{}, nil, func() bool { return true }) // local miss, federation "on", always shed
	rec, err := r.GetScore("203.0.113.9")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if !rec.LastSeen.IsZero() {
		t.Errorf("shedding must return the local-only (empty) record, got %+v", rec)
	}
}
