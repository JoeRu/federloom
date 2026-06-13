package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// pubKeyPrefix is the textual encoding prefix for Person identity public keys.
const pubKeyPrefix = "ed25519:"

// GeneratePersonKey creates a new Person identity key at path (mode 0600).
// It refuses to overwrite an existing key — a Person identity is long-lived
// and losing it invalidates every cert it ever signed.
func GeneratePersonKey(path string) (ed25519.PrivateKey, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("identity: person key already exists at %s — refusing to overwrite", path)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate person key: %w", err)
	}
	enc := base64.StdEncoding.EncodeToString(priv.Seed())
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("identity: create key dir: %w", err)
	}
	// Write atomically (temp + rename). A crash mid-write must not leave a
	// truncated key: GeneratePersonKey would then refuse to overwrite it and
	// LoadPersonKey would fail to parse it, stranding the identity forever.
	// O_EXCL on the temp also closes the stat-then-write TOCTOU between two
	// concurrent `identity init` invocations.
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("identity: create temp person key %s: %w", tmp, err)
	}
	_, werr := f.WriteString(enc + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("identity: write person key %s: write=%v close=%v", path, werr, cerr)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("identity: install person key %s: %w", path, err)
	}
	return priv, nil
}

// LoadPersonKey reads a Person identity key, enforcing private file permissions.
func LoadPersonKey(path string) (ed25519.PrivateKey, error) {
	if err := checkKeyPerms(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: read person key %s: %w", path, err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("identity: parse person key %s: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity: person key %s: bad seed length %d", path, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PersonPub extracts the public key of a Person identity.
func PersonPub(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

// EncodePub renders a Person public key as "ed25519:<base64>".
func EncodePub(pub ed25519.PublicKey) string {
	return pubKeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// DecodePub parses "ed25519:<base64>" into a Person public key.
func DecodePub(s string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(s, pubKeyPrefix) {
		return nil, fmt.Errorf("identity: pubkey %q: missing %q prefix", s, pubKeyPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, pubKeyPrefix))
	if err != nil {
		return nil, fmt.Errorf("identity: pubkey %q: %w", s, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity: pubkey %q: bad length %d", s, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// Fingerprint returns a short human-verifiable form of a Person public key:
// the first 8 bytes of SHA-256(pub) as hex in 4-char groups, e.g. "ab12 cd34 ef56 7890".
// Operators read this aloud over a channel they already trust (spec §5.1).
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	hexs := fmt.Sprintf("%x", sum[:8])
	return strings.Join([]string{hexs[0:4], hexs[4:8], hexs[8:12], hexs[12:16]}, " ")
}
