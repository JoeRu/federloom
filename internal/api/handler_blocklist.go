package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JoeRu/federloom/internal/store"
)

// blockEntry is one row in the JSON blocklist response.
type blockEntry struct {
	IP       string    `json:"ip"`
	Score    float64   `json:"score"`
	LastSeen time.Time `json:"last_seen"`
	Reasons  []string  `json:"reasons"`
}

// blocklistFilter holds the parsed query parameters shared by handleBlocklist
// and handleCrowdSecCTI.
type blocklistFilter struct {
	minScore       float64
	purpose        string
	reasonPatterns []string // non-nil when ?reason= is set
}

// parseBlocklistFilter reads the common query params from r.
func (s *Server) parseBlocklistFilter(r *http.Request) blocklistFilter {
	q := r.URL.Query()

	// min_score: default to BlockThreshold
	minScore := s.repCfg.BlockThreshold
	if raw := q.Get("min_score"); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			minScore = v
		}
	}

	// purpose: explicit param, then cfg default
	purpose := q.Get("purpose")
	if purpose == "" {
		purpose = s.cfg.Purpose
	}

	// reason: comma-separated direct patterns (overrides taxonomy lookup)
	var reasonPatterns []string
	if raw := q.Get("reason"); raw != "" {
		for _, p := range strings.Split(raw, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				reasonPatterns = append(reasonPatterns, p)
			}
		}
	}

	return blocklistFilter{
		minScore:       minScore,
		purpose:        purpose,
		reasonPatterns: reasonPatterns,
	}
}

// passRecord returns true when rec passes the score and reason/purpose filters.
func (s *Server) passRecord(rec store.ScoreRecord, f blocklistFilter, purposePatterns []string) bool {
	if rec.LastSeen.IsZero() {
		return false
	}
	if rec.Score < f.minScore {
		return false
	}
	if len(f.reasonPatterns) > 0 {
		// Direct reason pattern filter.
		if !MatchesPatterns(rec.Reasons, f.reasonPatterns) {
			return false
		}
	} else if len(purposePatterns) > 0 {
		// Taxonomy-based purpose filter.
		if !MatchesPatterns(rec.Reasons, purposePatterns) {
			return false
		}
	}
	return true
}

// handleBlocklist handles GET /api/v1/blocklist and returns a JSON array of
// all IPs whose score meets the threshold, ordered by score descending.
func (s *Server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	f := s.parseBlocklistFilter(r)

	// Resolve taxonomy patterns once (only when not using ?reason=).
	var purposePatterns []string
	if len(f.reasonPatterns) == 0 && f.purpose != "" {
		purposePatterns = PurposePatterns(s.taxonomy, f.purpose)
	}

	entries := []blockEntry{}
	_ = s.store.ScanScores(func(ip string, rec store.ScoreRecord) error {
		if s.passRecord(rec, f, purposePatterns) {
			entries = append(entries, blockEntry{
				IP:       ip,
				Score:    rec.Score,
				LastSeen: rec.LastSeen,
				Reasons:  rec.Reasons,
			})
		}
		return nil
	})

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Score > entries[j].Score
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

// handleCrowdSecCTI handles GET /crowdsec/v1/decisions and returns a plain-text
// list of blocked IPs (one per line), compatible with CrowdSec bouncer format.
func (s *Server) handleCrowdSecCTI(w http.ResponseWriter, r *http.Request) {
	f := s.parseBlocklistFilter(r)

	var purposePatterns []string
	if len(f.reasonPatterns) == 0 && f.purpose != "" {
		purposePatterns = PurposePatterns(s.taxonomy, f.purpose)
	}

	w.Header().Set("Content-Type", "text/plain")
	_ = s.store.ScanScores(func(ip string, rec store.ScoreRecord) error {
		if _, err := netip.ParseAddr(ip); err != nil {
			return nil
		}
		if s.passRecord(rec, f, purposePatterns) {
			fmt.Fprintln(w, ip)
		}
		return nil
	})
}
