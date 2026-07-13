//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/enforce"
	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
)

// mockSink is a single-goroutine test double for enforce.Sink.
type mockSink struct {
	blocked   []string
	unblocked []string
}

func (m *mockSink) Name() string                  { return "mock" }
func (m *mockSink) Start(_ context.Context) error { return nil }
func (m *mockSink) Block(ip string) error         { m.blocked = append(m.blocked, ip); return nil }
func (m *mockSink) BlockFor(ip string, _ time.Duration) error {
	m.blocked = append(m.blocked, ip)
	return nil
}
func (m *mockSink) Unblock(ip string) error { m.unblocked = append(m.unblocked, ip); return nil }
func (m *mockSink) Close() error            { return nil }

// Compile-time assertion that mockSink satisfies the enforce.Sink interface.
var _ enforce.Sink = (*mockSink)(nil)

// TestPipelineBlockAfterThreshold feeds three ssh-auth-success events for a
// public IP and verifies that Block is called exactly once (on the third record,
// when the logistic score crosses 75).
//
// Logistic progression with weight=40, trust=1.0:
//
//	record 1: 0  + 1.0*40*(1 - 0/100)  = 40.0
//	record 2: 40 + 1.0*40*(1 - 40/100) = 64.0
//	record 3: 64 + 1.0*40*(1 - 64/100) = 78.4  → crosses 75
func TestPipelineBlockAfterThreshold(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()

	engine := reputation.New(s, 7*24*time.Hour, 15, 0.15)
	sink := &mockSink{}

	const (
		ip               = "5.6.7.8"
		blockThreshold   = 75.0
		unblockThreshold = 60.0
	)

	for i := 0; i < 3; i++ {
		score, err := engine.Record(ip, "ssh-auth-success", "peer1", 1.0, "peer1", "", true)
		if err != nil {
			t.Fatalf("engine.Record (iteration %d): %v", i+1, err)
		}
		if score >= blockThreshold {
			if err := sink.Block(ip); err != nil {
				t.Fatalf("sink.Block: %v", err)
			}
			break
		}
	}

	if len(sink.blocked) != 1 {
		t.Fatalf("len(sink.blocked) = %d, want 1", len(sink.blocked))
	}
	if sink.blocked[0] != ip {
		t.Errorf("sink.blocked[0] = %q, want %q", sink.blocked[0], ip)
	}
}

// TestPipelineNeverBlockProtected verifies that a RFC1918 address is never
// passed to Block even when its score exceeds the block threshold.
func TestPipelineNeverBlockProtected(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()

	engine := reputation.New(s, 7*24*time.Hour, 15, 0.15)
	sink := &mockSink{}
	nbl := enforce.NewNeverBlockList(nil)

	const (
		ip             = "10.0.0.1"
		blockThreshold = 75.0
	)

	for i := 0; i < 3; i++ {
		score, err := engine.Record(ip, "ssh-auth-success", "peer1", 1.0, "peer1", "", true)
		if err != nil {
			t.Fatalf("engine.Record (iteration %d): %v", i+1, err)
		}
		if score >= blockThreshold {
			if nbl.Contains(ip) {
				// Protected — do not block.
				break
			}
			if err := sink.Block(ip); err != nil {
				t.Fatalf("sink.Block: %v", err)
			}
			break
		}
	}

	if len(sink.blocked) != 0 {
		t.Errorf("len(sink.blocked) = %d, want 0 (RFC1918 address must never be blocked)", len(sink.blocked))
	}
}

// TestPipelineUnblockAfterDecay verifies that after enough time passes for the
// score to decay well below the unblock threshold (60), Unblock is called.
//
// With a 500 ms half-life, sleeping 4 s covers 8 half-lives:
//
//	score ≈ 78.4 / 2^8 ≈ 0.3  (well below 60)
func TestPipelineUnblockAfterDecay(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()

	engine := reputation.New(s, 500*time.Millisecond, 15, 0.15)
	sink := &mockSink{}

	const (
		ip               = "9.8.7.6"
		blockThreshold   = 75.0
		unblockThreshold = 60.0
	)

	// Drive the score above the block threshold (3 records, same logistic progression).
	for i := 0; i < 3; i++ {
		score, err := engine.Record(ip, "ssh-auth-success", "peer1", 1.0, "peer1", "", true)
		if err != nil {
			t.Fatalf("engine.Record (iteration %d): %v", i+1, err)
		}
		if score >= blockThreshold {
			if err := sink.Block(ip); err != nil {
				t.Fatalf("sink.Block: %v", err)
			}
			break
		}
	}

	if len(sink.blocked) == 0 {
		t.Fatal("expected Block to have been called before decay test; score never crossed threshold")
	}

	// Wait 8 half-lives so the score decays to near zero.
	time.Sleep(4 * time.Second)

	if _, err := engine.Decay(ip); err != nil {
		t.Fatalf("engine.Decay: %v", err)
	}

	rec, err := engine.GetRecord(ip)
	if err != nil {
		t.Fatalf("engine.GetRecord: %v", err)
	}

	if rec.Score >= unblockThreshold {
		t.Fatalf("Score = %v after 8 half-lives, want < %v", rec.Score, unblockThreshold)
	}

	if err := sink.Unblock(ip); err != nil {
		t.Fatalf("sink.Unblock: %v", err)
	}

	if len(sink.unblocked) != 1 {
		t.Fatalf("len(sink.unblocked) = %d, want 1", len(sink.unblocked))
	}
	if sink.unblocked[0] != ip {
		t.Errorf("sink.unblocked[0] = %q, want %q", sink.unblocked[0], ip)
	}
}
