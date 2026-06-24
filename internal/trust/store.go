package trust

import (
	"log"
	"os"
	"sync"
	"time"

	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/pkg/proto"
)

// Store answers "how much do I trust this peer?" by combining the anchored
// Person identities (anchors.json, hot-reloaded) with a cache of verified
// peer-certs (on-wire vouches + locally imported certs).
type Store struct {
	anchorsPath    string
	certsPath      string
	blockedPath    string
	strangerWeight float64
	reloadEvery    time.Duration

	mu          sync.RWMutex
	anchors     map[string]Anchor         // keyed by IdentityPubkey
	certs       map[string]proto.PeerCert // peerID -> verified cert
	blocked     map[string]struct{}
	lastCheck   time.Time
	anchorsStat fileStat
	certsStat   fileStat
	blockedStat fileStat
	loadedOnce  bool
}

// fileStat is the change signal for a watched file. We combine mtime AND size
// because mtime resolution on some filesystems is coarse (1s) — two writes in
// the same tick share an mtime, so size disambiguates same-tick edits and the
// hot-reload (Invariant 6) stays reliable.
type fileStat struct {
	mtime time.Time
	size  int64
}

// NewStore creates a Store reading anchorsPath, certsPath, and blockedPath.
// strangerWeight is returned for any peer without a valid, anchored vouch.
func NewStore(anchorsPath, certsPath, blockedPath string, strangerWeight float64) *Store {
	s := &Store{
		anchorsPath:    anchorsPath,
		certsPath:      certsPath,
		blockedPath:    blockedPath,
		strangerWeight: strangerWeight,
		reloadEvery:    10 * time.Second,
		anchors:        map[string]Anchor{},
		certs:          map[string]proto.PeerCert{},
		blocked:        map[string]struct{}{},
	}
	// Eagerly load once so a later corrupt write has a last-good state to fall
	// back to (Invariant 6: a bad file must not silently drop existing trust).
	s.maybeReload(time.Now())
	return s
}

// SetReloadInterval overrides the file re-check interval (tests use 0).
func (s *Store) SetReloadInterval(d time.Duration) { s.reloadEvery = d }

// AddCert cryptographically verifies cert and caches it (on-wire vouch path).
// Anchoring of the Person key is checked later, in Resolve.
func (s *Store) AddCert(cert proto.PeerCert, now time.Time) error {
	if err := identity.VerifyCert(cert, now); err != nil {
		return err
	}
	s.mu.Lock()
	s.certs[cert.PeerID] = cert
	s.mu.Unlock()
	return nil
}

// Resolve returns the trust weight, the corroboration group (the Person name),
// and whether peerID is currently vouched by an anchored, non-expired Person.
func (s *Store) Resolve(peerID string) (weight float64, group string, anchored bool) {
	now := time.Now()
	s.maybeReload(now)

	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, ok := s.certs[peerID]
	if !ok || now.After(cert.ValidUntil) {
		return s.strangerWeight, "", false
	}
	a, ok := s.anchors[identity.EncodePub(cert.PersonKey)]
	if !ok || a.Expired(now) {
		return s.strangerWeight, "", false
	}
	return a.Weight, a.Person, true
}

// IsBlocked reports whether peerID is in the operator-managed blocked list
// (hot-reloaded from blocked-peers.json, spec §5.2 defederation).
func (s *Store) IsBlocked(peerID string) bool {
	now := time.Now()
	s.maybeReload(now)
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, blocked := s.blocked[peerID]
	return blocked
}

// maybeReload re-reads anchors.json and imported certs when their mtime moved.
// On a parse error after a successful load it keeps the last good state —
// the failure direction is "less trust", never "no trust we used to have".
func (s *Store) maybeReload(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loadedOnce && now.Sub(s.lastCheck) < s.reloadEvery {
		return
	}
	s.lastCheck = now

	if st, changed := statChanged(s.anchorsPath, s.anchorsStat); changed || !s.loadedOnce {
		anchors, err := LoadAnchors(s.anchorsPath)
		switch {
		case err != nil && s.loadedOnce:
			log.Printf("trust: reload %s failed, keeping last good anchors: %v", s.anchorsPath, err)
		case err != nil:
			log.Printf("trust: WARNING — cannot load %s, starting with NO anchors: %v", s.anchorsPath, err)
			s.anchors = map[string]Anchor{}
		default:
			m := make(map[string]Anchor, len(anchors))
			for _, a := range anchors {
				// Defend the resolver against a hand-edited anchors.json: weight
				// must stay in (0,1]. Clamp over-weight to 1.0 (never let a file
				// edit grant MORE than full trust); drop non-positive weights
				// (a zero-trust anchor is pointless). LoadAnchors stays pure so
				// federloomctl's read-modify-write doesn't lose entries.
				if a.Weight <= 0 {
					log.Printf("trust: dropping anchor %q with non-positive weight %v", a.Person, a.Weight)
					continue
				}
				if a.Weight > 1 {
					log.Printf("trust: clamping anchor %q weight %v to 1.0", a.Person, a.Weight)
					a.Weight = 1
				}
				m[a.IdentityPubkey] = a
			}
			s.anchors = m
			s.anchorsStat = st
		}
	}

	if st, changed := statChanged(s.certsPath, s.certsStat); changed || !s.loadedOnce {
		certs, err := LoadCerts(s.certsPath)
		if err != nil {
			log.Printf("trust: reload %s failed, keeping cached certs: %v", s.certsPath, err)
		} else {
			for _, c := range certs {
				if verr := identity.VerifyCert(c, now); verr != nil {
					continue
				}
				// Don't let a stale file cert clobber a fresher on-wire vouch
				// for the same peer: keep whichever lives longer.
				if existing, ok := s.certs[c.PeerID]; !ok || c.ValidUntil.After(existing.ValidUntil) {
					s.certs[c.PeerID] = c
				}
			}
			s.certsStat = st
		}
	}

	if s.blockedPath != "" {
		if st, changed := statChanged(s.blockedPath, s.blockedStat); changed || !s.loadedOnce {
			peers, err := LoadBlockedPeers(s.blockedPath)
			if err != nil {
				log.Printf("trust: reload %s failed, keeping last blocked list: %v", s.blockedPath, err)
			} else {
				m := make(map[string]struct{}, len(peers))
				for _, p := range peers {
					m[p] = struct{}{}
				}
				s.blocked = m
				s.blockedStat = st
			}
		}
	}

	s.loadedOnce = true
}

// statChanged stats path and reports whether its mtime+size differ from prev.
// Size disambiguates same-second writes when filesystem mtime resolution is
// coarse. A missing file always reports changed=true so removals are noticed.
func statChanged(path string, prev fileStat) (fileStat, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStat{}, true // missing file: always re-evaluate so removals are noticed
	}
	cur := fileStat{mtime: fi.ModTime(), size: fi.Size()}
	return cur, !cur.mtime.Equal(prev.mtime) || cur.size != prev.size
}
