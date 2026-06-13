package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/trust"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// labelPath stores the operator-chosen label next to the person key.
func labelPath(personKeyFile string) string { return personKeyFile + ".label" }

// issuedCertsPath stores every cert this Person has signed (for trust export).
func issuedCertsPath(personKeyFile string) string { return personKeyFile + ".issued.json" }

func cmdIdentity(args []string) error {
	if len(args) > 0 && args[0] == "init" {
		return identityInit(args[1:])
	}
	if len(args) > 0 && args[0] == "show" {
		return identityShow(args[1:])
	}

	fs := flag.NewFlagSet("identity", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	priv, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if err != nil {
		return err
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return err
	}
	fmt.Println(pid)
	return nil
}

func identityInit(args []string) error {
	fs := flag.NewFlagSet("identity init", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	label := fs.String("label", "", "human label for this Person identity (e.g. your name)")
	validFor := fs.Duration("valid-for", 365*24*time.Hour, "validity of the self peer-cert")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}

	priv, err := identity.GeneratePersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		return err
	}
	if *label != "" {
		if err := os.WriteFile(labelPath(cfg.TrustPersonKeyFile()), []byte(*label+"\n"), 0o644); err != nil {
			return fmt.Errorf("write label: %w", err)
		}
	}

	pub := identity.PersonPub(priv)
	fmt.Println("person identity created:", cfg.TrustPersonKeyFile())
	fmt.Println("public key: ", identity.EncodePub(pub))
	fmt.Println("fingerprint:", identity.Fingerprint(pub))

	// If this machine already has a node key, self-certify it so the local
	// swarmd publishes vouched events immediately.
	nodePriv, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if err != nil {
		fmt.Println("note: no node key yet — run `swarmctl peer-cert` after swarmd first start")
		return nil
	}
	pid, err := peer.IDFromPrivateKey(nodePriv)
	if err != nil {
		return err
	}
	cert := identity.IssueCert(priv, pid.String(), time.Now().Add(*validFor))
	if err := writeCert(cfg.TrustPeerCertFile(), cert); err != nil {
		return err
	}
	if err := appendIssuedCert(issuedCertsPath(cfg.TrustPersonKeyFile()), cert); err != nil {
		return err
	}
	fmt.Println("self peer-cert installed:", cfg.TrustPeerCertFile(), "(peer", pid.String()+")")
	return nil
}

func identityShow(args []string) error {
	fs := flag.NewFlagSet("identity show", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	priv, err := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		return err
	}
	pub := identity.PersonPub(priv)
	if data, err := os.ReadFile(labelPath(cfg.TrustPersonKeyFile())); err == nil {
		fmt.Printf("label:       %s", data)
	}
	fmt.Println("public key: ", identity.EncodePub(pub))
	fmt.Println("fingerprint:", identity.Fingerprint(pub))
	return nil
}

func cmdPeerCert(args []string) error {
	fs := flag.NewFlagSet("peer-cert", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	validFor := fs.Duration("valid-for", 365*24*time.Hour, "cert validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl peer-cert PEER_ID")
	}
	peerID := fs.Arg(0)
	if _, err := peer.Decode(peerID); err != nil {
		return fmt.Errorf("invalid peer ID %q: %w", peerID, err)
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	priv, err := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		return err
	}
	cert := identity.IssueCert(priv, peerID, time.Now().Add(*validFor))
	if err := appendIssuedCert(issuedCertsPath(cfg.TrustPersonKeyFile()), cert); err != nil {
		return err
	}
	out, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	fmt.Fprintln(os.Stderr, "→ save this JSON as peer.cert in the target node's store dir")
	return nil
}

func writeCert(path string, cert proto.PeerCert) error {
	data, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func appendIssuedCert(path string, cert proto.PeerCert) error {
	certs, err := trust.LoadCerts(path)
	if err != nil {
		return err
	}
	for i, c := range certs {
		if c.PeerID == cert.PeerID {
			certs[i] = cert
			return trust.SaveCerts(path, certs)
		}
	}
	return trust.SaveCerts(path, append(certs, cert))
}

// personPubMust loads the Person public key for self-anchor detection in trust.go.
func personPubMust(personKeyFile string) ed25519.PublicKey {
	priv, err := identity.LoadPersonKey(personKeyFile)
	if err != nil {
		return nil
	}
	return identity.PersonPub(priv)
}
