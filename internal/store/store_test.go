package store_test

import (
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/store"
)

func openTestStore(t *testing.T) *store.BadgerStore {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestGetScoreMissing(t *testing.T) {
	s := openTestStore(t)
	rec, err := s.GetScore("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Score != 0 {
		t.Errorf("expected zero score, got %v", rec.Score)
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	s := openTestStore(t)
	want := store.ScoreRecord{
		Score:         42.5,
		Corroboration: 2,
		FirstSeen:     time.Now().Truncate(time.Second),
		LastSeen:      time.Now().Truncate(time.Second),
		Reasons:       []string{"ssh-probe"},
		ReporterIDs:   []string{"peer1", "peer2"},
	}
	if err := s.PutScore("1.2.3.4", want, 24*time.Hour); err != nil {
		t.Fatalf("PutScore: %v", err)
	}
	got, err := s.GetScore("1.2.3.4")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if got.Score != want.Score {
		t.Errorf("Score: got %v, want %v", got.Score, want.Score)
	}
	if got.Corroboration != want.Corroboration {
		t.Errorf("Corroboration: got %v, want %v", got.Corroboration, want.Corroboration)
	}
}

func TestDeleteScore(t *testing.T) {
	s := openTestStore(t)
	_ = s.PutScore("1.2.3.4", store.ScoreRecord{Score: 10}, 24*time.Hour)
	if err := s.DeleteScore("1.2.3.4"); err != nil {
		t.Fatalf("DeleteScore: %v", err)
	}
	rec, err := s.GetScore("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error after delete: %v", err)
	}
	if rec.Score != 0 {
		t.Errorf("expected zero score after delete, got %v", rec.Score)
	}
}

func TestScanScores(t *testing.T) {
	s := openTestStore(t)
	_ = s.PutScore("1.1.1.1", store.ScoreRecord{Score: 10}, 24*time.Hour)
	_ = s.PutScore("2.2.2.2", store.ScoreRecord{Score: 20}, 24*time.Hour)
	seen := map[string]float64{}
	err := s.ScanScores(func(ip string, r store.ScoreRecord) error {
		seen[ip] = r.Score
		return nil
	})
	if err != nil {
		t.Fatalf("ScanScores: %v", err)
	}
	if len(seen) != 2 {
		t.Errorf("expected 2 entries, got %d", len(seen))
	}
	if seen["1.1.1.1"] != 10 || seen["2.2.2.2"] != 20 {
		t.Errorf("wrong scores: %v", seen)
	}
}
