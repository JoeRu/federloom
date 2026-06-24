package reputation_test

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
)

func openEngine(t *testing.T) *reputation.Engine {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return reputation.New(s, 7*24*time.Hour, 15)
}

func TestRecordIncreasesScore(t *testing.T) {
	e := openEngine(t)
	score, err := e.Record("1.2.3.4", "ssh-probe", "peer1", 1.0, "peer1", true)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if score <= 0 {
		t.Errorf("expected positive score, got %v", score)
	}
}

func TestSameReporterDoesNotIncreaseCorroboration(t *testing.T) {
	e := openEngine(t)
	_, _ = e.Record("1.2.3.4", "ssh-probe", "peer1", 1.0, "peer1", true)
	_, _ = e.Record("1.2.3.4", "ssh-probe", "peer1", 1.0, "peer1", true)
	rec, err := e.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Corroboration != 1 {
		t.Errorf("expected corroboration=1 for same reporter, got %d", rec.Corroboration)
	}
}

func TestTwoReportersIncreasesCorroboration(t *testing.T) {
	e := openEngine(t)
	_, _ = e.Record("1.2.3.4", "ssh-probe", "peer1", 1.0, "peer1", true)
	_, _ = e.Record("1.2.3.4", "ssh-probe", "peer2", 1.0, "peer2", true)
	rec, err := e.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Corroboration != 2 {
		t.Errorf("expected corroboration=2, got %d", rec.Corroboration)
	}
}

func TestScoreNeverExceeds100(t *testing.T) {
	e := openEngine(t)
	for i := 0; i < 100; i++ {
		score, err := e.Record("1.2.3.4", "ssh-auth-success", "peer1", 1.0, "peer1", true)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if score > 100 {
			t.Fatalf("score exceeded 100: %v at iteration %d", score, i)
		}
	}
}
