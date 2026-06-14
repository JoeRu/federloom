package rules

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/pkg/proto"
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

// RuleSet holds the loaded rules and hot-reloads them when the backing file changes.
type RuleSet struct {
	mu       sync.RWMutex
	rules    []Rule
	path     string
	lastStat fileStat
	fallback float64 // score threshold used when rules list is empty (legacy mode)
}

// Load returns a RuleSet backed by path. If path is empty or the file does not
// exist, Evaluate uses fallbackThreshold for legacy score-based blocking.
func Load(path string, fallbackThreshold float64) *RuleSet {
	rs := &RuleSet{path: path, fallback: fallbackThreshold}
	rs.reload()
	return rs
}

// Evaluate returns the action for the given event + reputation state.
// It hot-reloads the rule file when mtime or size has changed since the last call.
func (rs *RuleSet) Evaluate(e proto.Event, rec store.ScoreRecord, b *BurstStore) Action {
	rs.maybeReload()

	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if len(rs.rules) == 0 {
		if rec.Score >= rs.fallback {
			return ActionBlock
		}
		return ActionNone
	}

	// burstCache memoises Count() calls for the same BurstWindow within one
	// Evaluate() invocation so we don't re-scan the slice per rule.
	now := time.Now()
	burstCache := make(map[time.Duration]int)

	for _, r := range rs.rules {
		if r.Reason != "" && r.Reason != e.Reason {
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
			cnt, ok := burstCache[w]
			if !ok {
				cnt = b.Count(e.IP, e.Reason, w, now)
				burstCache[w] = cnt
			}
			if cnt < r.MinBurst {
				continue
			}
		}
		return r.Action
	}
	return ActionNone
}

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
	rs.reload()
}

func (rs *RuleSet) reload() {
	if rs.path == "" {
		return
	}
	data, err := os.ReadFile(rs.path)
	if err != nil {
		return // file missing = legacy mode; suppress log spam on fresh installs
	}
	var loaded []Rule
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		log.Printf("rules: keeping last-good ruleset; parse error in %s: %v", rs.path, err)
		return
	}
	info, _ := os.Stat(rs.path)
	rs.mu.Lock()
	rs.rules = loaded
	if info != nil {
		rs.lastStat = fileStat{mtime: info.ModTime(), size: info.Size()}
	}
	rs.mu.Unlock()
}
