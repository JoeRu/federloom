package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// cmdSetup runs the interactive first-time setup wizard (spec §5.1):
//  1. Ensures a node key exists (swarmd must have run once)
//  2. Creates or loads a Person identity
//  3. Installs a self peer-cert binding the node key to the Person identity
func cmdSetup(args []string) error {
	fset := flag.NewFlagSet("setup", flag.ExitOnError)
	loadCfg := addConfigFlag(fset)
	label := fset.String("label", "", "your name / label for the Person identity (skips stdin prompt)")
	if err := fset.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}

	fmt.Println("[1/3] Node key")
	nodePriv, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if err != nil {
		fmt.Fprintln(os.Stderr, "      swarmd must run once first to generate the node key — then re-run setup.")
		return err
	}
	pid, err := peer.IDFromPrivateKey(nodePriv)
	if err != nil {
		return err
	}
	fmt.Printf("      peer ID: %s\n", pid)

	fmt.Println("[2/3] Person identity")
	personPriv, err := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || os.IsNotExist(err) {
			// Determine label — flag or interactive prompt
			chosenLabel := *label
			if chosenLabel == "" {
				fmt.Print("      Enter your name (label for this identity): ")
				scanner := bufio.NewScanner(os.Stdin)
				if scanner.Scan() {
					chosenLabel = strings.TrimSpace(scanner.Text())
				}
			}
			if chosenLabel == "" {
				return fmt.Errorf("label is required for a new Person identity")
			}

			fmt.Print("      creating person.key...")
			personPriv, err = identity.GeneratePersonKey(cfg.TrustPersonKeyFile())
			if err != nil {
				return err
			}
			if err := os.WriteFile(labelPath(cfg.TrustPersonKeyFile()), []byte(chosenLabel+"\n"), 0o644); err != nil {
				return fmt.Errorf("write label: %w", err)
			}
			fmt.Println(" done")
		} else {
			return err
		}
	}

	pub := identity.PersonPub(personPriv)
	fmt.Printf("      public key:  %s\n", identity.EncodePub(pub))
	fp := identity.Fingerprint(pub)
	fmt.Printf("      fingerprint: %s\n", fp)

	fmt.Println("[3/3] Peer certificate")
	certPath := cfg.TrustPeerCertFile()
	certData, err := os.ReadFile(certPath)
	if err == nil {
		// Cert already exists — show its expiry
		var cert proto.PeerCert
		if jsonErr := json.Unmarshal(certData, &cert); jsonErr != nil {
			return fmt.Errorf("parse peer cert %s: %w", certPath, jsonErr)
		}
		remaining := time.Until(cert.ValidUntil)
		days := int(remaining.Hours() / 24)
		fmt.Printf("      peer.cert valid until %s  (%dd remaining)\n",
			cert.ValidUntil.Format("2006-01-02"), days)
	} else if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
		// Issue a fresh self cert
		fmt.Print("      self-certifying this node...")
		validUntil := time.Now().Add(365 * 24 * time.Hour)
		cert := identity.IssueCert(ed25519.PrivateKey(personPriv), pid.String(), validUntil)
		if err := writeCert(certPath, cert); err != nil {
			return err
		}
		if err := appendIssuedCert(issuedCertsPath(cfg.TrustPersonKeyFile()), cert); err != nil {
			return err
		}
		fmt.Println(" done")
		fmt.Printf("      installed: %s  (valid 365d)\n", certPath)
	} else {
		return fmt.Errorf("read peer cert %s: %w", certPath, err)
	}

	fmt.Printf(`
Setup complete.

Share your fingerprint (%s) with operators you want to federate with.
Next: swarmctl federation invite --addr /ip4/YOUR_IP/tcp/7700 > invite.json
`, fp)
	return nil
}

// cmdStatus and cmdFederation will be implemented in Tasks 3 and 4.
func cmdStatus(args []string) error    { return fmt.Errorf("not yet implemented") }
func cmdFederation(args []string) error { return fmt.Errorf("not yet implemented") }
