package store_test

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/store"
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

func TestScoreRecordTrustFieldsRoundTrip(t *testing.T) {
	s := openTestStore(t)

	rec := store.ScoreRecord{
		Score:           42,
		Groups:          []string{"jo", "alice"},
		StrangerSeen:    true,
		StrangerContrib: 7.5,
		LastSeen:        time.Now(),
	}
	if err := s.PutScore("192.0.2.7", rec, time.Hour); err != nil {
		t.Fatalf("PutScore: %v", err)
	}
	got, err := s.GetScore("192.0.2.7")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if len(got.Groups) != 2 || got.Groups[0] != "jo" {
		t.Errorf("Groups = %v, want [jo alice]", got.Groups)
	}
	if !got.StrangerSeen {
		t.Error("StrangerSeen lost")
	}
	if got.StrangerContrib != 7.5 {
		t.Errorf("StrangerContrib = %v, want 7.5", got.StrangerContrib)
	}
}

func TestBloom_UnknownIPReturnsZero(t *testing.T) {
	s := openTestStore(t)
	rec, err := s.GetScore("203.0.113.1")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if rec.Score != 0 || !rec.LastSeen.IsZero() {
		t.Errorf("expected zero ScoreRecord for unknown IP, got %+v", rec)
	}
}

func TestBloom_NoFalseNegative(t *testing.T) {
	s := openTestStore(t)
	want := store.ScoreRecord{
		Score:    55,
		LastSeen: time.Now().Truncate(time.Second),
	}
	if err := s.PutScore("198.51.100.7", want, 24*time.Hour); err != nil {
		t.Fatalf("PutScore: %v", err)
	}
	got, err := s.GetScore("198.51.100.7")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if got.Score != want.Score {
		t.Errorf("Score: got %v, want %v — bloom false negative", got.Score, want.Score)
	}
}

func TestBloom_RebuildOnReopen(t *testing.T) {
	dir := t.TempDir()

	// First instance: write an entry and close.
	s1, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open s1: %v", err)
	}
	rec := store.ScoreRecord{Score: 99, LastSeen: time.Now().Truncate(time.Second)}
	if err := s1.PutScore("10.0.0.1", rec, 24*time.Hour); err != nil {
		t.Fatalf("PutScore: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close s1: %v", err)
	}

	// Second instance: bloom must be rebuilt from the startup scan.
	s2, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open s2: %v", err)
	}
	defer s2.Close()

	got, err := s2.GetScore("10.0.0.1")
	if err != nil {
		t.Fatalf("GetScore after reopen: %v", err)
	}
	if got.Score != 99 {
		t.Errorf("Score: got %v, want 99 — bloom not rebuilt from DB on reopen", got.Score)
	}
}
