// Package resources — good-neighbour controls: a processing-rate budget and
// load shedding under overload (spec §11.5). The Governor never sheds local
// protection work; callers gate only network-contribution work on Shed().
package resources

import (
	"sync"
	"time"
)

const (
	govBuckets        = 10                     // 100ms buckets → a 1s sliding window
	bucketDur         = 100 * time.Millisecond // width of one bucket
	sheddExitFraction = 0.8                    // exit shed only when rate ≤ 0.8×budget (hysteresis)
)

// Governor is a concurrency-safe processing-rate meter with a shed decision.
// maxPerSec <= 0 disables it (never sheds). The window is a ring of per-100ms
// buckets summed over the last second; no background goroutine — buckets are
// advanced lazily on Charge/Shed/Rate.
type Governor struct {
	mu        sync.Mutex
	maxPerSec float64
	now       func() time.Time // injectable for tests
	counts    [govBuckets]int
	lastTick  int64 // 100ms tick of the most recent advance; -1 = never charged
	shedding  bool
}

// NewGovernor builds a Governor with a per-second budget. budget <= 0 = off.
func NewGovernor(maxPerSec float64) *Governor {
	return &Governor{maxPerSec: maxPerSec, now: time.Now, lastTick: -1}
}

func (g *Governor) tick() int64 { return g.now().UnixNano() / int64(bucketDur) }

// advanceLocked zeros the buckets for ticks elapsed since lastTick. Holds mu.
func (g *Governor) advanceLocked(t int64) {
	if g.lastTick < 0 {
		g.lastTick = t
		return
	}
	elapsed := t - g.lastTick
	if elapsed <= 0 {
		return
	}
	if elapsed >= govBuckets {
		for i := range g.counts {
			g.counts[i] = 0
		}
	} else {
		for i := int64(1); i <= elapsed; i++ {
			g.counts[(g.lastTick+i)%govBuckets] = 0
		}
	}
	g.lastTick = t
}

func (g *Governor) rateLocked() float64 {
	sum := 0
	for _, c := range g.counts {
		sum += c
	}
	return float64(sum) // events in the last 1s window == events/sec
}

// Charge records one unit of processed work against the current window.
func (g *Governor) Charge() {
	if g.maxPerSec <= 0 {
		return
	}
	g.mu.Lock()
	t := g.tick()
	g.advanceLocked(t)
	g.counts[t%govBuckets]++
	g.mu.Unlock()
}

// Shed reports whether the node is over budget and sheddable work should skip.
// Hysteresis: enters at the budget, exits only at ≤ sheddExitFraction×budget.
func (g *Governor) Shed() bool {
	if g.maxPerSec <= 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.advanceLocked(g.tick())
	rate := g.rateLocked()
	if g.shedding {
		if rate <= g.maxPerSec*sheddExitFraction {
			g.shedding = false
		}
	} else if rate >= g.maxPerSec {
		g.shedding = true
	}
	return g.shedding
}

// Rate returns the current events/sec over the last window.
func (g *Governor) Rate() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.advanceLocked(g.tick())
	return g.rateLocked()
}
