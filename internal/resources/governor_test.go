package resources

import (
	"sync"
	"testing"
	"time"
)

func TestGovernorSheddingWithHysteresis(t *testing.T) {
	base := time.Unix(1000, 0)
	clk := base
	g := NewGovernor(100) // 100 events/sec budget
	g.now = func() time.Time { return clk }

	// Below budget: charge 50 in the current second → not shedding.
	for i := 0; i < 50; i++ {
		g.Charge()
	}
	if g.Shed() {
		t.Fatalf("50/s under a 100/s budget must not shed; rate=%v", g.Rate())
	}

	// Push over budget in the same 1s window → shedding.
	for i := 0; i < 60; i++ {
		g.Charge()
	}
	if !g.Shed() {
		t.Fatalf("110/s over a 100/s budget must shed; rate=%v", g.Rate())
	}

	// Advance ~0.6s (past the exit fraction as old buckets fall out is not enough
	// yet); advance a full 1s so the window empties → rate 0 ≤ 0.8×budget → exit.
	clk = base.Add(1100 * time.Millisecond)
	if g.Shed() {
		t.Errorf("after the 1s window empties, must exit shed mode; rate=%v", g.Rate())
	}
}

// TestGovernorHysteresisMargin proves the shed state STAYS engaged while the
// rate sits in the (0.8×budget, budget) band and clears only once it drops to
// ≤ 0.8×budget — i.e. the hysteresis margin actually exists and does not flap.
// Charges are spread one-per-bucket so the rate can decay through the band as
// buckets age out, rather than emptying all at once.
func TestGovernorHysteresisMargin(t *testing.T) {
	base := time.Unix(2000, 0)
	clk := base
	g := NewGovernor(10) // budget 10 → exit threshold 0.8×10 = 8
	g.now = func() time.Time { return clk }

	// Fill all 10 buckets with 1 each (rate == 10) without advancing past the
	// last charge, so the window holds exactly 10.
	for i := 0; i < govBuckets; i++ {
		g.Charge()
		if i < govBuckets-1 {
			clk = clk.Add(bucketDur)
		}
	}
	if !g.Shed() {
		t.Fatalf("rate 10 ≥ budget 10 must shed; rate=%v", g.Rate())
	}

	// Age out one bucket → rate 9, still inside the band (8 < 9 < 10): must
	// STAY shedding (this is the hysteresis — a plain rate<budget exit would
	// wrongly clear here).
	clk = clk.Add(bucketDur)
	if !g.Shed() {
		t.Fatalf("rate 9 is above the 8 exit threshold — must stay shedding; rate=%v", g.Rate())
	}

	// Age out two more → rate 7 ≤ 8 → exit.
	clk = clk.Add(2 * bucketDur)
	if g.Shed() {
		t.Errorf("rate 7 ≤ 0.8×budget must exit shed mode; rate=%v", g.Rate())
	}
}

func TestGovernorDisabled(t *testing.T) {
	g := NewGovernor(0) // unlimited / off
	for i := 0; i < 100000; i++ {
		g.Charge()
	}
	if g.Shed() {
		t.Error("budget 0 must never shed")
	}
	// Charge must be a genuine no-op when disabled: the rate meter stays at 0.
	// (Guards against a regression that drops the maxPerSec<=0 check in Charge.)
	if r := g.Rate(); r != 0 {
		t.Errorf("disabled governor must not accumulate rate, got %v", r)
	}
}

func TestGovernorRaceSafe(t *testing.T) {
	g := NewGovernor(1000)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				g.Charge()
				_ = g.Shed()
				_ = g.Rate()
			}
		}()
	}
	wg.Wait()
}
