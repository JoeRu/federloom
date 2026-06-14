package observability

import (
	"context"
	"database/sql"
	"log"
	"math"
	"time"

	"github.com/JoeRu/swarmguard/pkg/proto"
	_ "modernc.org/sqlite"
)

type sqliteOutput struct {
	db        *sql.DB
	retention time.Duration
	halfLife  time.Duration
	threshold float64
}

func newSQLiteOutput(path string, retention, halfLife time.Duration, threshold float64) (*sqliteOutput, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := initSQLiteSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &sqliteOutput{db: db, retention: retention, halfLife: halfLife, threshold: threshold}, nil
}

func initSQLiteSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id       INTEGER PRIMARY KEY AUTOINCREMENT,
			ts       INTEGER NOT NULL,
			ip       TEXT    NOT NULL,
			reason   TEXT    NOT NULL,
			reporter TEXT    NOT NULL,
			subnet   TEXT    NOT NULL DEFAULT '',
			score    REAL    NOT NULL
		);
		CREATE INDEX IF NOT EXISTS events_ts ON events(ts);

		CREATE TABLE IF NOT EXISTS rule_firings (
			id     INTEGER PRIMARY KEY AUTOINCREMENT,
			ts     INTEGER NOT NULL,
			ip     TEXT    NOT NULL,
			rule   TEXT    NOT NULL,
			action TEXT    NOT NULL,
			score  REAL    NOT NULL
		);
		CREATE INDEX IF NOT EXISTS rule_firings_ts ON rule_firings(ts);

		CREATE TABLE IF NOT EXISTS blocks (
			id               INTEGER PRIMARY KEY AUTOINCREMENT,
			ip               TEXT    NOT NULL,
			blocked_at       INTEGER NOT NULL,
			unblocked_at     INTEGER,
			score_at_block   REAL    NOT NULL,
			expected_unblock INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS blocks_ip ON blocks(ip);
	`)
	return err
}

func (s *sqliteOutput) recordEvent(e proto.Event, score float64) {
	_, err := s.db.Exec(
		`INSERT INTO events(ts,ip,reason,reporter,subnet,score) VALUES(?,?,?,?,?,?)`,
		time.Now().Unix(), e.IP, e.Reason, e.ReporterID, e.SubnetID, score,
	)
	if err != nil {
		log.Printf("observability: sqlite event: %v", err)
	}
}

func (s *sqliteOutput) recordRuleFiring(e proto.Event, score float64, rule, action string) {
	_, err := s.db.Exec(
		`INSERT INTO rule_firings(ts,ip,rule,action,score) VALUES(?,?,?,?,?)`,
		time.Now().Unix(), e.IP, rule, action, score,
	)
	if err != nil {
		log.Printf("observability: sqlite rule_firing: %v", err)
	}
}

func (s *sqliteOutput) recordBlock(ip string, score float64) {
	now := time.Now()
	expectedUnblock := s.computeUnblock(score, now)
	_, err := s.db.Exec(
		`INSERT INTO blocks(ip,blocked_at,score_at_block,expected_unblock) VALUES(?,?,?,?)`,
		ip, now.Unix(), score, expectedUnblock.Unix(),
	)
	if err != nil {
		log.Printf("observability: sqlite block: %v", err)
	}
}

func (s *sqliteOutput) recordUnblock(ip string) {
	_, err := s.db.Exec(
		`UPDATE blocks SET unblocked_at=? WHERE ip=? AND unblocked_at IS NULL`,
		time.Now().Unix(), ip,
	)
	if err != nil {
		log.Printf("observability: sqlite unblock: %v", err)
	}
}

// computeUnblock returns the estimated time when score decays below threshold.
// Formula: t = halfLife × log2(score / threshold).
// When score <= threshold, log2 ≤ 0, so we return now (already at/below threshold).
func (s *sqliteOutput) computeUnblock(score float64, now time.Time) time.Time {
	if score <= s.threshold {
		return now
	}
	nanos := float64(s.halfLife) * math.Log2(score/s.threshold)
	return now.Add(time.Duration(nanos))
}

func (s *sqliteOutput) sweep() {
	cutoff := time.Now().Add(-s.retention).Unix()
	for _, q := range []string{
		`DELETE FROM events       WHERE ts < ?`,
		`DELETE FROM rule_firings WHERE ts < ?`,
		`DELETE FROM blocks       WHERE blocked_at < ? AND unblocked_at IS NOT NULL`,
	} {
		if _, err := s.db.Exec(q, cutoff); err != nil {
			log.Printf("observability: retention sweep: %v", err)
		}
	}
}

func (s *sqliteOutput) startRetentionSweep(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.sweep()
			case <-ctx.Done():
				_ = s.db.Close()
				return
			}
		}
	}()
}
