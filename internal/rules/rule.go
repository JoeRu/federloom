package rules

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// Action is the outcome of a matched rule.
type Action string

const (
	ActionBlock  Action = "block"
	ActionWatch  Action = "watch"
	ActionIgnore Action = "ignore"
	ActionNone   Action = "" // no rule matched
)

// duration wraps time.Duration to support YAML unmarshalling from strings
// like "10m", "1h". Same pattern as config.Duration in internal/config.
type duration struct{ time.Duration }

func (d *duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("rules: parse duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// Rule is a single named rule. All present conditions must match (AND logic).
// The first matching rule in the list wins.
type Rule struct {
	Name             string   `yaml:"name"`
	Reason           string   `yaml:"reason"`
	MinScore         float64  `yaml:"min_score"`
	MinCorroboration int      `yaml:"min_corroboration"`
	AnchoredOnly     bool     `yaml:"anchored_only"`
	MinBurst         int      `yaml:"min_burst"`
	BurstWindow      duration `yaml:"burst_window"`
	Action           Action   `yaml:"action"`
}

type fileStat struct {
	mtime time.Time
	size  int64
}

// burstCacheKey identifies a burst count query by both reason and window so
// that two rules with the same burst_window but different reasons do not share
// a cached count (Fix 3).
type burstCacheKey struct {
	reason string
	window time.Duration
}

// RuleSet holds the loaded rules and hot-reloads them when the backing file changes.
type RuleSet struct {
	mu          sync.RWMutex // protects rules and lastStat for readers
	reloadMu    sync.Mutex   // serialises file reload attempts (Fix 1)
	rules       []Rule
	path        string
	lastStat    fileStat
	fallback    float64 // score threshold used when rules list is empty (legacy mode)
	strangerCap float64 // stranger_score_cap; used only by the load-time lint (advisory)
	loaded      bool    // true after first successful file read (Fix 2)
}

// Load returns a RuleSet backed by path. If path is empty or the file does not
// exist, Evaluate uses fallbackThreshold for legacy score-based blocking.
// strangerScoreCap is used only by the advisory load-time lint (lintBlockRules).
func Load(path string, fallbackThreshold, strangerScoreCap float64) *RuleSet {
	rs := &RuleSet{path: path, fallback: fallbackThreshold, strangerCap: strangerScoreCap}
	rs.reload()
	// Legacy-mode advisory: with no rules file, a bare score >= fallback blocks.
	// If fallback is below the stranger cap, stranger-only score could reach it —
	// the node-level backstop still prevents the block, but warn the operator.
	if len(rs.rules) == 0 && rs.fallback < rs.strangerCap {
		log.Printf("rules: legacy fallback threshold (%.0f) is below stranger_score_cap (%.0f); stranger-only score could reach it, but the node-level backstop prevents the block", rs.fallback, rs.strangerCap)
	}
	return rs
}

// Evaluate returns the action and matched rule name for the given event + reputation state.
// Rule name is empty when no rule matched (legacy fallback or ActionNone).
// It hot-reloads the rule file when mtime or size has changed since the last call.
func (rs *RuleSet) Evaluate(e proto.Event, rec store.ScoreRecord, b *BurstStore) (Action, string) {
	rs.maybeReload()

	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if len(rs.rules) == 0 {
		if rec.Score >= rs.fallback {
			return ActionBlock, ""
		}
		return ActionNone, ""
	}

	// burstCache memoises Count() calls for the same (reason, BurstWindow) pair
	// within one Evaluate() invocation so we don't re-scan the slice per rule.
	// The key includes reason to prevent cross-reason cache collisions (Fix 3).
	now := time.Now()
	burstCache := make(map[burstCacheKey]int)

	for _, r := range rs.rules {
		if r.Reason != "" && !matchReason(r.Reason, e.Reason) {
			continue
		}
		if r.MinScore > 0 && rec.Score < r.MinScore {
			continue
		}
		if r.MinCorroboration > 0 && rec.Corroboration < r.MinCorroboration {
			continue
		}
		if r.AnchoredOnly && rec.StrangerSeen {
			continue
		}
		if r.MinBurst > 0 {
			w := r.BurstWindow.Duration
			ck := burstCacheKey{reason: e.Reason, window: w}
			cnt, ok := burstCache[ck]
			if !ok {
				cnt = b.Count(e.IP, e.Reason, w, now)
				burstCache[ck] = cnt
			}
			if cnt < r.MinBurst {
				continue
			}
		}
		return r.Action, r.Name
	}
	return ActionNone, ""
}

// maybeReload checks whether the backing file has changed and calls reload()
// if so. It uses a double-checked locking pattern with reloadMu to ensure
// only one goroutine parses the file at a time (Fix 1).
func (rs *RuleSet) maybeReload() {
	if rs.path == "" {
		return
	}
	info, err := os.Stat(rs.path)
	if err != nil {
		return
	}
	cur := fileStat{mtime: info.ModTime(), size: info.Size()}
	rs.mu.RLock()
	unchanged := cur == rs.lastStat
	rs.mu.RUnlock()
	if unchanged {
		return
	}
	// Serialise reload — only one goroutine parses the file at a time.
	rs.reloadMu.Lock()
	defer rs.reloadMu.Unlock()
	// Re-check after acquiring lock; another goroutine may have reloaded already.
	rs.mu.RLock()
	unchanged = cur == rs.lastStat
	rs.mu.RUnlock()
	if unchanged {
		return
	}
	rs.reload()
}

func (rs *RuleSet) reload() {
	if rs.path == "" {
		return
	}
	data, err := os.ReadFile(rs.path)
	if err != nil {
		// Fix 2: after a successful initial load, warn instead of silently dropping.
		rs.mu.RLock()
		alreadyLoaded := rs.loaded
		rs.mu.RUnlock()
		if alreadyLoaded {
			log.Printf("rules: keeping last-good ruleset; read error for %s: %v", rs.path, err)
		}
		return // file missing = legacy mode; suppress log spam on fresh installs
	}
	var loaded []Rule
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		log.Printf("rules: keeping last-good ruleset; parse error in %s: %v", rs.path, err)
		return
	}
	// Fix 4: drop misconfigured rules before installing them.
	loaded = validateRules(loaded, rs.path)
	for _, w := range lintBlockRules(loaded, rs.strangerCap) {
		log.Printf("rules: %s", w)
	}
	info, _ := os.Stat(rs.path)
	rs.mu.Lock()
	rs.rules = loaded
	rs.loaded = true
	if info != nil {
		rs.lastStat = fileStat{mtime: info.ModTime(), size: info.Size()}
	}
	rs.mu.Unlock()
}

// matchReason returns true if pattern matches reason.
// A pattern ending in "*" is a prefix match; otherwise exact equality.
func matchReason(pattern, reason string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(reason, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == reason
}

// validateRules filters out rules that would cause incorrect behaviour at
// runtime so that a misconfigured file does not silently produce wrong results.
// Each dropped rule is logged (Fix 4).
func validateRules(rules []Rule, path string) []Rule {
	valid := rules[:0:0] // new slice, avoids mutating the original backing array
	for _, r := range rules {
		if r.MinBurst > 0 && r.BurstWindow.Duration == 0 {
			log.Printf("rules: skipping rule %q in %s: min_burst set but burst_window is zero", r.Name, path)
			continue
		}
		switch r.Action {
		case ActionBlock, ActionWatch, ActionIgnore:
			// ok
		default:
			log.Printf("rules: skipping rule %q in %s: unknown action %q", r.Name, path, r.Action)
			continue
		}
		valid = append(valid, r)
	}
	return valid
}

// lintBlockRules returns one advisory warning per block rule that could fire on
// un-anchored (stranger) input. A block rule is stranger-safe when it requires
// anchored evidence or a threshold strangers cannot reach:
//   - min_corroboration >= 1  (corroboration counts anchored groups only, P0-1)
//   - anchored_only            (gated on anchored evidence)
//   - min_burst >= 1           (only anchored reporters feed the burst window, P0-2)
//   - min_score > strangerCap  (a stranger's score is capped at or below this)
//
// Non-block rules are ignored. Warnings are advisory: the node-level backstop
// already guarantees no stranger-only block is applied.
func lintBlockRules(rules []Rule, strangerCap float64) []string {
	var warnings []string
	for _, r := range rules {
		if r.Action != ActionBlock {
			continue
		}
		safe := r.MinCorroboration >= 1 || r.AnchoredOnly || r.MinBurst >= 1 || r.MinScore > strangerCap
		if !safe {
			warnings = append(warnings, fmt.Sprintf("rule %q can block on un-anchored (stranger) input: no min_corroboration, no anchored_only, no min_burst, and min_score (%.0f) < stranger_score_cap (%.0f); the node-level backstop will downgrade such blocks to watch", r.Name, r.MinScore, strangerCap))
		}
	}
	return warnings
}
