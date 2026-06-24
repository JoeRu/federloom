package trust

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Anchor is one trusted Person identity — an entry of anchors.json
// (spec §5.1/§7.3, source is always "self-added" in this phase).
// The Person is the corroboration unit: every peer they certify
// inherits Weight and counts toward the same group.
type Anchor struct {
	Person         string    `json:"person"`          // local short name, chosen by THIS operator
	Label          string    `json:"label"`           // free-text description
	IdentityPubkey string    `json:"identity_pubkey"` // "ed25519:<base64>"
	Weight         float64   `json:"weight"`          // trust weight in (0,1]
	ValidUntil     time.Time `json:"valid_until"`     // zero = no expiry
	Source         string    `json:"source"`          // "self-added"
}

// Expired reports whether the anchor itself has lapsed.
func (a Anchor) Expired(now time.Time) bool {
	return !a.ValidUntil.IsZero() && now.After(a.ValidUntil)
}

// LoadAnchors reads anchors from path. A missing file is an empty list, not an error.
func LoadAnchors(path string) ([]Anchor, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", path, err)
	}
	var anchors []Anchor
	if err := json.Unmarshal(data, &anchors); err != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", path, err)
	}
	return anchors, nil
}

// SaveAnchors writes anchors atomically (temp file + rename) so a concurrently
// reading federloomd never sees a half-written file.
func SaveAnchors(path string, anchors []Anchor) error {
	data, err := json.MarshalIndent(anchors, "", "  ")
	if err != nil {
		return fmt.Errorf("trust: marshal anchors: %w", err)
	}
	return atomicWrite(path, data)
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("trust: create dir for %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("trust: temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("trust: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("trust: close temp: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("trust: rename into %s: %w", path, err)
	}
	return nil
}
