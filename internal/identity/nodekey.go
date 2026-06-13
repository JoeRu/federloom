package identity

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/libp2p/go-libp2p/core/crypto"
)

// LoadOrCreateNodeKey returns the node's persistent libp2p identity key,
// generating an Ed25519 key at path (mode 0600) on first run. The derived
// peer ID is stable across restarts — the prerequisite for being vouched
// for and trusted by other operators (spec §5.1).
func LoadOrCreateNodeKey(path string) (crypto.PrivKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if err := checkKeyPerms(path); err != nil {
			return nil, err
		}
		priv, err := crypto.UnmarshalPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("identity: parse node key %s: %w", path, err)
		}
		return priv, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("identity: read node key %s: %w", path, err)
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return nil, fmt.Errorf("identity: generate node key: %w", err)
	}
	raw, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal node key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("identity: create key dir: %w", err)
	}
	// Write atomically: a crash mid-write must not leave a truncated key file,
	// which would be unrecoverable (the node identity would be lost). Temp file
	// in the same dir + rename is atomic on Linux for same-filesystem moves.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("identity: write node key %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("identity: install node key %s: %w", path, err)
	}
	return priv, nil
}

// checkKeyPerms refuses keys readable by group or others — same posture as SSH.
func checkKeyPerms(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("identity: stat %s: %w", path, err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("identity: %s has mode %v — must not be group/world-accessible, run: chmod 600 %s", path, fi.Mode().Perm(), path)
	}
	return nil
}
