package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"github.com/JoeRu/federloom/pkg/proto"
)

// WhitelistStore is the local operator-managed IP/CIDR allowlist (spec §6.2 / §7.4).
// Loaded once at node startup from a JSON file; call Add/Remove to mutate the file.
// federloomd reads the file at startup only — no hot-reload in this phase.
type WhitelistStore struct {
	path    string
	mu      sync.RWMutex
	entries []proto.WhitelistEntry
}

// LoadWhitelist opens path and loads the whitelist. A missing file returns an
// empty store without error — the file is created on the first Add call.
func LoadWhitelist(path string) (*WhitelistStore, error) {
	w := &WhitelistStore{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return w, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read whitelist %s: %w", path, err)
	}
	if len(data) == 0 {
		return w, nil
	}
	if err := json.Unmarshal(data, &w.entries); err != nil {
		return nil, fmt.Errorf("store: parse whitelist %s: %w", path, err)
	}
	return w, nil
}

// Contains returns true if ip is covered by any entry in the store.
// Handles exact IP matches, CIDR containment, IPv4 and IPv6, and IPv4-mapped IPv6.
func (w *WhitelistStore) Contains(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, entry := range w.entries {
		if entryAddr, err := netip.ParseAddr(entry.IPOrRange); err == nil {
			if entryAddr.Unmap().Compare(addr) == 0 {
				return true
			}
			continue
		}
		if prefix, err := netip.ParsePrefix(entry.IPOrRange); err == nil {
			if prefix.Masked().Contains(addr) {
				return true
			}
		}
	}
	return false
}

// Add appends entry to the store. If an entry with the same IPOrRange already
// exists it is not duplicated (idempotent). Persists the updated list to disk.
func (w *WhitelistStore) Add(entry proto.WhitelistEntry) error {
	w.mu.Lock()
	for _, e := range w.entries {
		if e.IPOrRange == entry.IPOrRange {
			w.mu.Unlock()
			return nil
		}
	}
	w.entries = append(w.entries, entry)
	snap := make([]proto.WhitelistEntry, len(w.entries))
	copy(snap, w.entries)
	w.mu.Unlock()
	return whitelistSave(w.path, snap)
}

// Remove deletes the entry with IPOrRange equal to ipOrRange. If no such entry
// exists it returns nil — not an error. Persists the updated list to disk.
func (w *WhitelistStore) Remove(ipOrRange string) error {
	w.mu.Lock()
	filtered := make([]proto.WhitelistEntry, 0, len(w.entries))
	for _, e := range w.entries {
		if e.IPOrRange != ipOrRange {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == len(w.entries) {
		w.mu.Unlock()
		return nil
	}
	w.entries = filtered
	snap := make([]proto.WhitelistEntry, len(w.entries))
	copy(snap, w.entries)
	w.mu.Unlock()
	return whitelistSave(w.path, snap)
}

// List returns a copy of all entries.
func (w *WhitelistStore) List() []proto.WhitelistEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]proto.WhitelistEntry, len(w.entries))
	copy(out, w.entries)
	return out
}

// whitelistSave marshals entries and atomically writes them to path.
func whitelistSave(path string, entries []proto.WhitelistEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal whitelist: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("store: write whitelist tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("store: rename whitelist: %w", err)
	}
	return nil
}
