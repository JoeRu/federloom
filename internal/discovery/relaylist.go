package discovery

import (
	"encoding/json"
	"fmt"
	"os"
)

// RelayEntry is one bootstrap/relay node from the bundled or operator-supplied list.
type RelayEntry struct {
	PeerID string   `json:"peer_id"` // libp2p peer ID string
	Addrs  []string `json:"addrs"`   // multiaddrs without /p2p/ suffix
	Label  string   `json:"label"`   // human-readable name
}

// LoadRelayList returns relay entries from path (if non-empty and the file exists)
// or falls back to the embedded bytes. Returns an error only on JSON parse failure
// of the custom file — a missing custom file silently falls back to embedded.
func LoadRelayList(path string, embedded []byte) ([]RelayEntry, error) {
	var data []byte
	if path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				data = embedded // fall back to bundled list
			} else {
				return nil, fmt.Errorf("discovery: read relay list %q: %w", path, err)
			}
		}
	} else {
		data = embedded
	}

	if len(data) == 0 {
		return nil, nil
	}
	var entries []RelayEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("discovery: parse relay list: %w", err)
	}
	return entries, nil
}
