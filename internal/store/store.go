package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// ScoreRecord is the internal on-disk reputation record for one IP.
// ReporterIDs/Groups are tracking metadata never sent on the wire.
type ScoreRecord struct {
	Score           float64   `json:"score"`
	Corroboration   int       `json:"corroboration"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Reasons         []string  `json:"reasons"`
	ReporterIDs     []string  `json:"reporter_ids"`
	Groups          []string  `json:"groups,omitempty"`           // distinct anchored Person names that reported this IP
	StrangerSeen    bool      `json:"stranger_seen,omitempty"`    // at least one un-anchored reporter
	StrangerContrib float64   `json:"stranger_contrib,omitempty"` // cumulative score points added by strangers (capped)
}

// BadgerStore wraps BadgerDB for reputation persistence.
type BadgerStore struct {
	db    *badger.DB
	bloom *repBloom
}

// Open opens (or creates) a BadgerDB at dir and rebuilds the bloom pre-filter
// from existing entries.
func Open(dir string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(dir).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("store: open badger at %q: %w", dir, err)
	}
	s := &BadgerStore{db: db, bloom: newBloom()}
	// Error intentionally ignored: a partial scan still warms the bloom, and a
	// scan failure must not prevent the store from opening. Worst case a missed
	// IP causes one redundant DB read, never a false negative.
	_ = s.ScanScores(func(ip string, _ ScoreRecord) error {
		s.bloom.Add(ip)
		return nil
	})
	return s, nil
}

// Close releases the BadgerDB resources.
func (s *BadgerStore) Close() error { return s.db.Close() }

// GetScore returns the ScoreRecord for ip, or a zero ScoreRecord if not found.
// Callers check rec.LastSeen.IsZero() to detect missing entries.
func (s *BadgerStore) GetScore(ip string) (ScoreRecord, error) {
	if !s.bloom.MightContain(ip) {
		return ScoreRecord{}, nil // definitely absent; skip DB read
	}
	var rec ScoreRecord
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(ip))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &rec)
		})
	})
	if err != nil {
		return ScoreRecord{}, fmt.Errorf("store: get %q: %w", ip, err)
	}
	return rec, nil
}

// PutScore persists rec for ip with the given TTL.
func (s *BadgerStore) PutScore(ip string, rec ScoreRecord, ttl time.Duration) error {
	val, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("store: marshal %q: %w", ip, err)
	}
	if err := s.db.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry([]byte(ip), val).WithTTL(ttl)
		return txn.SetEntry(entry)
	}); err != nil {
		return err
	}
	s.bloom.Add(ip)
	return nil
}

// DeleteScore removes the record for ip.
func (s *BadgerStore) DeleteScore(ip string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(ip))
	})
}

// ScanScores calls fn for every stored IP. Stops on first error from fn.
func (s *BadgerStore) ScanScores(fn func(ip string, r ScoreRecord) error) error {
	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			ip := string(item.KeyCopy(nil))
			var rec ScoreRecord
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &rec)
			}); err != nil {
				return err
			}
			if err := fn(ip, rec); err != nil {
				return err
			}
		}
		return nil
	})
}
