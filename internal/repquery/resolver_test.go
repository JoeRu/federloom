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
	r := NewResolver(local, nil) // nil querier: if it tried to federate it'd panic
	got, err := r.GetScore("1.1.1.1")
	if err != nil || got.Score != 50 {
		t.Fatalf("local hit not returned: %+v err=%v", got, err)
	}
}

func TestResolverMissNoQuerierReturnsEmpty(t *testing.T) {
	r := NewResolver(fixedStore{}, nil) // local miss (zero record), no federation
	got, _ := r.GetScore("2.2.2.2")
	if !got.LastSeen.IsZero() {
		t.Errorf("expected empty record on miss with no querier, got %+v", got)
	}
}
