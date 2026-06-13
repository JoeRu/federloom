package trust

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/JoeRu/swarmguard/pkg/proto"
)

// LoadCerts reads locally imported peer-certs (seeded by `swarmctl trust import`).
// Missing file = empty list.
func LoadCerts(path string) ([]proto.PeerCert, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", path, err)
	}
	var certs []proto.PeerCert
	if err := json.Unmarshal(data, &certs); err != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", path, err)
	}
	return certs, nil
}

// SaveCerts writes the imported-cert list atomically.
func SaveCerts(path string, certs []proto.PeerCert) error {
	data, err := json.MarshalIndent(certs, "", "  ")
	if err != nil {
		return fmt.Errorf("trust: marshal certs: %w", err)
	}
	return atomicWrite(path, data)
}
