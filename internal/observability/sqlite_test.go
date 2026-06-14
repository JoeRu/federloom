package observability

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/pkg/proto"
	// modernc.org/sqlite driver is registered by sqlite.go (same package)
)

func openTestSQLite(t *testing.T) *sqliteOutput {
	t.Helper()
	sq, err := newSQLiteOutput(
		filepath.Join(t.TempDir(), "test.db"),
		30*24*time.Hour, // retention: 30 days
		7*24*time.Hour,  // halfLife: 1 week
		75.0,            // blockThreshold
	)
	if err != nil {
		t.Fatalf("newSQLiteOutput: %v", err)
	}
	t.Cleanup(func() { sq.db.Close() })
	return sq
}

func TestSQLiteOutput_RecordEvent(t *testing.T) {
	sq := openTestSQLite(t)
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1", SubnetID: "s1"}
	sq.recordEvent(e, 42.0)

	var count int
	sq.db.QueryRow("SELECT COUNT(*) FROM events WHERE ip='1.2.3.4' AND reason='ssh-probe'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 event row, got %d", count)
	}
}

func TestSQLiteOutput_RecordRuleFiring(t *testing.T) {
	sq := openTestSQLite(t)
	e := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: "peer1"}
	sq.recordRuleFiring(e, 80.0, "ssh-burst", "block")

	var rule, action string
	sq.db.QueryRow("SELECT rule, action FROM rule_firings WHERE ip='1.2.3.4'").Scan(&rule, &action)
	if rule != "ssh-burst" || action != "block" {
		t.Errorf("rule=%q action=%q, want ssh-burst/block", rule, action)
	}
}

func TestSQLiteOutput_RecordBlock_DueTime_InFuture(t *testing.T) {
	sq := openTestSQLite(t)
	sq.recordBlock("1.2.3.4", 150.0) // score well above threshold

	var expectedUnblock int64
	sq.db.QueryRow("SELECT expected_unblock FROM blocks WHERE ip='1.2.3.4'").Scan(&expectedUnblock)
	if expectedUnblock <= time.Now().Unix() {
		t.Errorf("expected_unblock should be in the future for score > threshold, got %d", expectedUnblock)
	}
}

func TestSQLiteOutput_RecordBlock_AtThreshold_DueTimeNow(t *testing.T) {
	sq := openTestSQLite(t)
	sq.recordBlock("1.2.3.4", 75.0) // exactly at threshold → due now

	var expectedUnblock int64
	sq.db.QueryRow("SELECT expected_unblock FROM blocks WHERE ip='1.2.3.4'").Scan(&expectedUnblock)
	// log2(75/75) = 0, so expected_unblock ≈ blocked_at
	if expectedUnblock > time.Now().Add(5*time.Second).Unix() {
		t.Errorf("score at threshold should produce near-zero due-time, got %d", expectedUnblock)
	}
}

func TestSQLiteOutput_RecordUnblock(t *testing.T) {
	sq := openTestSQLite(t)
	sq.recordBlock("1.2.3.4", 80.0)
	sq.recordUnblock("1.2.3.4")

	var unblockedAt sql.NullInt64
	sq.db.QueryRow("SELECT unblocked_at FROM blocks WHERE ip='1.2.3.4'").Scan(&unblockedAt)
	if !unblockedAt.Valid {
		t.Error("unblocked_at should be set after recordUnblock")
	}
}

func TestSQLiteOutput_RetentionSweep_DeletesOld(t *testing.T) {
	sq := openTestSQLite(t)
	oldTs := time.Now().Add(-60 * 24 * time.Hour).Unix()
	sq.db.Exec("INSERT INTO events(ts,ip,reason,reporter,score) VALUES(?,?,?,?,?)",
		oldTs, "1.2.3.4", "ssh-probe", "peer1", 10.0)
	sq.recordEvent(proto.Event{IP: "5.6.7.8", Reason: "ssh-probe", ReporterID: "peer2"}, 20.0)

	sq.sweep()

	var count int
	sq.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 event after sweep (old deleted), got %d", count)
	}
}

func TestSQLiteOutput_RetentionSweep_KeepsActiveBlocks(t *testing.T) {
	sq := openTestSQLite(t)
	// Insert a block that is old but still active (unblocked_at IS NULL)
	oldTs := time.Now().Add(-60 * 24 * time.Hour).Unix()
	sq.db.Exec("INSERT INTO blocks(ip,blocked_at,score_at_block,expected_unblock) VALUES(?,?,?,?)",
		"1.2.3.4", oldTs, 80.0, oldTs+3600)

	sq.sweep()

	var count int
	sq.db.QueryRow("SELECT COUNT(*) FROM blocks WHERE ip='1.2.3.4' AND unblocked_at IS NULL").Scan(&count)
	if count != 1 {
		t.Errorf("active block should not be pruned by retention sweep")
	}
}
