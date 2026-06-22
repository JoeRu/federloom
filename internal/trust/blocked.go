package trust

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadBlockedPeers reads the blocked-peer list from path.
// A missing file is an empty list, not an error (safe default).
func LoadBlockedPeers(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read blocked peers %s: %w", path, err)
	}
	var peers []string
	if err := json.Unmarshal(data, &peers); err != nil {
		return nil, fmt.Errorf("trust: parse blocked peers %s: %w", path, err)
	}
	return peers, nil
}

// SaveBlockedPeers writes the blocked-peer list atomically.
func SaveBlockedPeers(path string, peers []string) error {
	data, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return fmt.Errorf("trust: marshal blocked peers: %w", err)
	}
	return atomicWrite(path, data)
}
