package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// helpers

// eval is a test helper that discards the rule-name return value for brevity.
func eval(rs *RuleSet, e proto.Event, rec store.ScoreRecord, b *BurstStore) Action {
	a, _ := rs.Evaluate(e, rec, b)
	return a
}

func noRec() store.ScoreRecord { return store.ScoreRecord{} }

func recScore(s float64) store.ScoreRecord { return store.ScoreRecord{Score: s} }

func recCorr(c int) store.ScoreRecord { return store.ScoreRecord{Corroboration: c} }

func recAnchored() store.ScoreRecord {
	return store.ScoreRecord{Corroboration: 1, StrangerSeen: false}
}

func recStranger() store.ScoreRecord {
	return store.ScoreRecord{Corroboration: 1, StrangerSeen: true}
}

func ev(reason string) proto.Event { return proto.Event{IP: "1.2.3.4", Reason: reason} }

func emptyBurst() *BurstStore { return NewBurstStore() }

// --- tests ---

func TestEvaluate_LegacyFallback_Block(t *testing.T) {
	rs := Load("", 75)
	got := eval(rs, ev("ssh-probe"), recScore(80), emptyBurst())
	if got != ActionBlock {
		t.Errorf("score=80 > fallback=75: got %v, want block", got)
	}
}

func TestEvaluate_LegacyFallback_NoBlock(t *testing.T) {
	rs := Load("", 75)
	got := eval(rs, ev("ssh-probe"), recScore(50), emptyBurst())
	if got != ActionNone {
		t.Errorf("score=50 < fallback=75: got %v, want none", got)
	}
}

func TestEvaluate_ReasonMatch(t *testing.T) {
	path := writeRules(t, `
- name: ssh-only
  reason: ssh-probe
  min_corroboration: 1
  action: block
`)
	rs := Load(path, 75)
	// matching reason
	if got := eval(rs, ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionBlock {
		t.Errorf("matching reason: got %v, want block", got)
	}
	// non-matching reason
	if got := eval(rs, ev("smtp-auth-bruteforce"), recCorr(1), emptyBurst()); got != ActionNone {
		t.Errorf("non-matching reason: got %v, want none", got)
	}
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	path := writeRules(t, `
- name: first
  reason: ssh-probe
  min_corroboration: 1
  action: watch
- name: second
  reason: ssh-probe
  min_corroboration: 1
  action: block
`)
	rs := Load(path, 75)
	got := eval(rs, ev("ssh-probe"), recCorr(1), emptyBurst())
	if got != ActionWatch {
		t.Errorf("first-match-wins: got %v, want watch", got)
	}
}

func TestEvaluate_MinCorroboration(t *testing.T) {
	path := writeRules(t, `
- name: needs-3
  reason: ssh-probe
  min_corroboration: 3
  action: block
`)
	rs := Load(path, 999)
	if got := eval(rs, ev("ssh-probe"), recCorr(2), emptyBurst()); got != ActionNone {
		t.Errorf("corroboration=2 < 3: got %v, want none", got)
	}
	if got := eval(rs, ev("ssh-probe"), recCorr(3), emptyBurst()); got != ActionBlock {
		t.Errorf("corroboration=3 >= 3: got %v, want block", got)
	}
}

func TestEvaluate_AnchoredOnly(t *testing.T) {
	path := writeRules(t, `
- name: anchored-only
  reason: ssh-probe
  min_corroboration: 1
  anchored_only: true
  action: block
`)
	rs := Load(path, 999)
	if got := eval(rs, ev("ssh-probe"), recStranger(), emptyBurst()); got != ActionNone {
		t.Errorf("stranger: got %v, want none", got)
	}
	if got := eval(rs, ev("ssh-probe"), recAnchored(), emptyBurst()); got != ActionBlock {
		t.Errorf("anchored: got %v, want block", got)
	}
}

func TestEvaluate_MinBurst(t *testing.T) {
	path := writeRules(t, `
- name: burst-rule
  reason: ssh-probe
  min_burst: 3
  burst_window: 1m
  action: block
`)
	rs := Load(path, 999)
	b := NewBurstStore()
	base := time.Now()

	// 2 events — not enough
	b.Record("1.2.3.4", "ssh-probe", base)
	b.Record("1.2.3.4", "ssh-probe", base)

	// Evaluate with a custom burst check: inject 2 events then check
	// We need to peek inside via Count to verify, but Evaluate uses time.Now()
	// internally. Add 2 records and verify ActionNone, then 3rd to trigger.
	if got := eval(rs, ev("ssh-probe"), noRec(), b); got != ActionNone {
		t.Errorf("burst=2 < 3: got %v, want none", got)
	}

	// 3rd event — fires
	b.Record("1.2.3.4", "ssh-probe", base)
	if got := eval(rs, ev("ssh-probe"), noRec(), b); got != ActionBlock {
		t.Errorf("burst=3 >= 3: got %v, want block", got)
	}
}

func TestEvaluate_HotReload(t *testing.T) {
	path := writeRules(t, `
- name: first-version
  reason: ssh-probe
  min_corroboration: 1
  action: watch
`)
	rs := Load(path, 999)
	if got := eval(rs, ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionWatch {
		t.Fatalf("before reload: got %v, want watch", got)
	}

	// Overwrite with a different rule; bump mtime explicitly to avoid
	// filesystem 1-second granularity surprises (Fix 5).
	writeRulesAndBumpMtime(t, path, `
- name: second-version
  reason: ssh-probe
  min_corroboration: 1
  action: block
`)
	if got := eval(rs, ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionBlock {
		t.Errorf("after reload: got %v, want block", got)
	}
}

func TestEvaluate_CorruptFileKeepsLastGood(t *testing.T) {
	path := writeRules(t, `
- name: good-rule
  reason: ssh-probe
  min_corroboration: 1
  action: block
`)
	rs := Load(path, 999)
	if got := eval(rs, ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionBlock {
		t.Fatalf("initial load: got %v, want block", got)
	}
	// Bump mtime explicitly so the hot-reload path is triggered (Fix 5).
	writeRulesAndBumpMtime(t, path, `:::not yaml:::`)
	// Must still use last-good ruleset
	if got := eval(rs, ev("ssh-probe"), recCorr(1), emptyBurst()); got != ActionBlock {
		t.Errorf("after corrupt file: got %v, want block (last-good)", got)
	}
}

func TestEvaluate_BurstCacheIsolatedByReason(t *testing.T) {
	path := writeRules(t, `
- name: ssh-burst
  reason: ssh-probe
  min_burst: 2
  burst_window: 1m
  action: block
- name: smtp-burst
  reason: smtp-auth-bruteforce
  min_burst: 2
  burst_window: 1m
  action: block
`)
	rs := Load(path, 999)
	b := NewBurstStore()
	base := time.Now()

	// Only record ssh-probe events
	b.Record("1.2.3.4", "ssh-probe", base)
	b.Record("1.2.3.4", "ssh-probe", base)

	// ssh-probe rule fires
	if got := eval(rs, ev("ssh-probe"), noRec(), b); got != ActionBlock {
		t.Errorf("ssh-probe burst: got %v, want block", got)
	}
	// smtp rule must NOT fire — different reason, zero smtp burst count
	if got := eval(rs, ev("smtp-auth-bruteforce"), noRec(), b); got != ActionNone {
		t.Errorf("smtp burst with no smtp events: got %v, want none", got)
	}
}

func TestEvaluate_InvalidActionDropped(t *testing.T) {
	path := writeRules(t, `
- name: typo-action
  reason: ssh-probe
  min_corroboration: 1
  action: bloc
- name: valid-fallback
  reason: ssh-probe
  min_corroboration: 1
  action: watch
`)
	rs := Load(path, 999)
	// The typo rule must be dropped; the valid fallback fires instead
	got := eval(rs, ev("ssh-probe"), recCorr(1), emptyBurst())
	if got != ActionWatch {
		t.Errorf("invalid action dropped: got %v, want watch", got)
	}
}

func TestEvaluate_BurstWithoutWindowDropped(t *testing.T) {
	path := writeRules(t, `
- name: missing-window
  reason: ssh-probe
  min_burst: 3
  action: block
- name: valid-fallback
  reason: ssh-probe
  min_corroboration: 1
  action: watch
`)
	rs := Load(path, 999)
	// The misconfigured burst rule must be dropped; the valid fallback fires
	got := eval(rs, ev("ssh-probe"), recCorr(1), emptyBurst())
	if got != ActionWatch {
		t.Errorf("burst-without-window dropped: got %v, want watch", got)
	}
}

func TestEvaluate_ReturnsRuleName(t *testing.T) {
	path := writeRules(t, `
- name: my-rule
  reason: ssh-probe
  min_corroboration: 1
  action: block
`)
	rs := Load(path, 75)
	action, name := rs.Evaluate(ev("ssh-probe"), recCorr(1), emptyBurst())
	if action != ActionBlock {
		t.Errorf("action = %v, want block", action)
	}
	if name != "my-rule" {
		t.Errorf("name = %q, want my-rule", name)
	}
}

func TestEvaluate_NoMatch_EmptyName(t *testing.T) {
	rs := Load("", 75)
	_, name := rs.Evaluate(ev("ssh-probe"), recScore(10), emptyBurst())
	if name != "" {
		t.Errorf("name = %q, want empty on no match", name)
	}
}

// --- helpers ---

func writeRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRulesTo(t, path, content)
	return path
}

func writeRulesTo(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write rules file: %v", err)
	}
}

// writeRulesAndBumpMtime writes content to path and then advances the file's
// mtime by one second so that hot-reload detection is reliable on filesystems
// with 1-second mtime granularity (Fix 5).
func writeRulesAndBumpMtime(t *testing.T, path, content string) {
	t.Helper()
	writeRulesTo(t, path, content)
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("bump mtime: %v", err)
	}
}
