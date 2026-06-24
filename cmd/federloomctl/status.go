package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/trust"
	"github.com/JoeRu/federloom/pkg/proto"
)

func cmdStatus(args []string) error {
	fset := flag.NewFlagSet("status", flag.ExitOnError)
	loadCfg := addConfigFlag(fset)
	if err := fset.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}

	now := time.Now()

	// ── NODE ─────────────────────────────────────────────────────────────────
	fmt.Println("NODE")
	nodeKeyPath := cfg.NodeKeyFile()
	if _, err := os.Stat(nodeKeyPath); errors.Is(err, fs.ErrNotExist) {
		fmt.Println("  peer ID:     not configured — run federloomctl setup")
		fmt.Printf("  node key:    %s  ✗\n", nodeKeyPath)
	} else {
		nodePriv, err := identity.LoadOrCreateNodeKey(nodeKeyPath)
		if err != nil {
			return fmt.Errorf("load node key: %w", err)
		}
		pid, err := peer.IDFromPrivateKey(nodePriv)
		if err != nil {
			return fmt.Errorf("derive peer ID: %w", err)
		}
		fmt.Printf("  peer ID:     %s\n", pid)
		fmt.Printf("  node key:    %s  ✓\n", nodeKeyPath)
	}
	fmt.Println()

	// ── IDENTITY ─────────────────────────────────────────────────────────────
	fmt.Println("IDENTITY")
	personPriv, personErr := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if personErr != nil {
		fmt.Println("  not configured — run federloomctl setup")
		fmt.Println()
	} else {
		pub := identity.PersonPub(personPriv)
		fp := identity.Fingerprint(pub)

		label := "(no label)"
		if data, err := os.ReadFile(labelPath(cfg.TrustPersonKeyFile())); err == nil {
			label = string(bytes.TrimSpace(data))
		}

		fmt.Printf("  person:      %s\n", label)
		fmt.Printf("  fingerprint: %s\n", fp)

		certData, certErr := os.ReadFile(cfg.TrustPeerCertFile())
		if certErr == nil {
			var cert proto.PeerCert
			if jsonErr := json.Unmarshal(certData, &cert); jsonErr != nil {
				return fmt.Errorf("parse peer cert %s: %w", cfg.TrustPeerCertFile(), jsonErr)
			}
			remaining := time.Until(cert.ValidUntil)
			days := int(remaining.Hours() / 24)
			fmt.Printf("  peer cert:   valid until %s  (%dd remaining)\n",
				cert.ValidUntil.Format("2006-01-02"), days)
		} else {
			fmt.Println("  peer cert:   not found — run federloomctl setup")
		}
		fmt.Println()
	}

	// ── TRUST ANCHORS ────────────────────────────────────────────────────────
	certs, _ := trust.LoadCerts(cfg.TrustCertsFile())
	anchors, err := trust.LoadAnchors(cfg.TrustAnchorsFile())
	if err != nil {
		return fmt.Errorf("load anchors: %w", err)
	}

	type anchorRow struct {
		person string
		weight float64
		status string
		fp     string
		label  string
	}

	var rows []anchorRow

	// Synthesize a "self" row from the local person key (if loaded).
	if personErr == nil {
		pub := identity.PersonPub(personPriv)
		fp := identity.Fingerprint(pub)

		selfLabel := "(no label)"
		if data, err := os.ReadFile(labelPath(cfg.TrustPersonKeyFile())); err == nil {
			selfLabel = string(bytes.TrimSpace(data))
		}

		selfStatus := "no-certs"
		for _, c := range certs {
			if bytes.Equal(c.PersonKey, []byte(pub)) {
				if now.Before(c.ValidUntil) {
					selfStatus = "ok"
				} else {
					selfStatus = "certs-exp"
				}
				break
			}
		}

		rows = append(rows, anchorRow{
			person: selfLabel,
			weight: 1.00,
			status: selfStatus,
			fp:     fp,
			label:  "self",
		})
	}

	// Add rows for each anchor.
	for _, a := range anchors {
		fp := "?"
		var pubRaw []byte
		if pub, err := identity.DecodePub(a.IdentityPubkey); err == nil {
			fp = identity.Fingerprint(pub)
			pubRaw = pub
		}
		rows = append(rows, anchorRow{
			person: a.Person,
			weight: a.Weight,
			status: anchorStatus(a, certs, pubRaw, now),
			fp:     fp,
			label:  a.Label,
		})
	}

	fmt.Printf("TRUST ANCHORS  (%d)\n", len(rows))
	if len(rows) == 0 {
		fmt.Println("  not configured — run federloomctl setup")
	} else {
		fmt.Printf("  %-12s %-7s %-9s %-22s %s\n", "PERSON", "WEIGHT", "STATUS", "FINGERPRINT", "LABEL")
		for _, r := range rows {
			fmt.Printf("  %-12s %-7.2f %-9s %-22s %s\n", r.person, r.weight, r.status, r.fp, r.label)
		}
	}
	fmt.Println()

	// ── BOOTSTRAP PEERS ──────────────────────────────────────────────────────
	fmt.Printf("BOOTSTRAP PEERS  (%d)\n", len(cfg.BootstrapPeers))
	if len(cfg.BootstrapPeers) == 0 {
		fmt.Println("  not configured — run federloomctl setup")
	} else {
		for _, p := range cfg.BootstrapPeers {
			fmt.Printf("  %s\n", p)
		}
	}
	fmt.Println()
	fmt.Println("  For live peer count: GET /api/v1/blocklist or check node logs.")

	return nil
}
