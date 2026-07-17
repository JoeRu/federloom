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

func TestGovernorDisabled(t *testing.T) {
	g := NewGovernor(0) // unlimited / off
	for i := 0; i < 100000; i++ {
		g.Charge()
	}
	if g.Shed() {
		t.Error("budget 0 must never shed")
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
