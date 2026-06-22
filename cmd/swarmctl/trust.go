package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/trust"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

func cmdTrust(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: swarmctl trust add|set|remove|list|export|import|block|unblock ...")
	}
	switch args[0] {
	case "add":
		return trustAdd(args[1:])
	case "set":
		return trustSet(args[1:])
	case "remove":
		return trustRemove(args[1:])
	case "list":
		return trustList(args[1:])
	case "export":
		return trustExport(args[1:])
	case "import":
		return trustImport(args[1:])
	case "block":
		return trustBlock(args[1:])
	case "unblock":
		return trustUnblock(args[1:])
	default:
		return fmt.Errorf("unknown trust subcommand %q", args[0])
	}
}

func trustAdd(args []string) error {
	fs := flag.NewFlagSet("trust add", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	idStr := fs.String("identity", "", "Person public key (ed25519:...)")
	weight := fs.Float64("weight", 0, "trust weight in (0,1] (default: config anchor_weight)")
	label := fs.String("label", "", "free-text label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl trust add PERSON --identity ed25519:...")
	}
	person := fs.Arg(0)
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	if *weight == 0 {
		*weight = cfg.Trust.AnchorWeight
	}
	if *weight <= 0 || *weight > 1 {
		return fmt.Errorf("weight %v out of range (0,1]", *weight)
	}
	pub, err := identity.DecodePub(*idStr)
	if err != nil {
		return err
	}
	own, err := ownPersonPub(cfg.TrustPersonKeyFile())
	if err != nil {
		return err
	}
	if own != nil && bytes.Equal(own, pub) {
		fmt.Println("that is your own identity — local events already run at trust 1.0; nothing to do")
		return nil
	}
	return upsertAnchor(cfg, trust.Anchor{
		Person:         person,
		Label:          *label,
		IdentityPubkey: identity.EncodePub(pub),
		Weight:         *weight,
		Source:         "self-added",
	})
}

func trustSet(args []string) error {
	fs := flag.NewFlagSet("trust set", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	weight := fs.Float64("weight", -1, "new trust weight in (0,1]")
	label := fs.String("label", "", "new label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl trust set PERSON [--weight W] [--label L]")
	}
	person := fs.Arg(0)
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	anchors, err := trust.LoadAnchors(cfg.TrustAnchorsFile())
	if err != nil {
		return err
	}
	for i := range anchors {
		if anchors[i].Person == person {
			if *weight >= 0 {
				if *weight <= 0 || *weight > 1 {
					return fmt.Errorf("weight %v out of range (0,1]", *weight)
				}
				anchors[i].Weight = *weight
			}
			if *label != "" {
				anchors[i].Label = *label
			}
			if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), anchors); err != nil {
				return err
			}
			fmt.Printf("updated %s (weight %.2f)\n", person, anchors[i].Weight)
			return nil
		}
	}
	return fmt.Errorf("no anchored person %q — see `swarmctl trust list`", person)
}

func trustRemove(args []string) error {
	fs := flag.NewFlagSet("trust remove", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl trust remove PERSON")
	}
	person := fs.Arg(0)
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	anchors, err := trust.LoadAnchors(cfg.TrustAnchorsFile())
	if err != nil {
		return err
	}
	kept := anchors[:0]
	removed := false
	for _, a := range anchors {
		if a.Person == person {
			removed = true
			continue
		}
		kept = append(kept, a)
	}
	if !removed {
		return fmt.Errorf("no anchored person %q", person)
	}
	if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), kept); err != nil {
		return err
	}
	fmt.Printf("removed %s — all their machines now score as strangers (takes effect within 10s)\n", person)
	return nil
}

func trustList(args []string) error {
	fs := flag.NewFlagSet("trust list", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	anchors, err := trust.LoadAnchors(cfg.TrustAnchorsFile())
	if err != nil {
		return err
	}
	if len(anchors) == 0 {
		fmt.Println("no anchored persons — see `swarmctl trust add`")
		return nil
	}
	// Load the imported certs so STATUS can report actual cert coverage per
	// Person, not just the (unused) anchor-level expiry.
	certs, _ := trust.LoadCerts(cfg.TrustCertsFile())
	now := time.Now()

	fmt.Printf("%-12s %-7s %-9s %-22s %s\n", "PERSON", "WEIGHT", "STATUS", "FINGERPRINT", "LABEL")
	for _, a := range anchors {
		fp := "?"
		var pubRaw []byte
		if pub, err := identity.DecodePub(a.IdentityPubkey); err == nil {
			fp = identity.Fingerprint(pub)
			pubRaw = pub
		}
		fmt.Printf("%-12s %-7.2f %-9s %-22s %s\n", a.Person, a.Weight, anchorStatus(a, certs, pubRaw, now), fp, a.Label)
	}
	return nil
}

// anchorStatus summarises a Person's live trust coverage: EXPIRED if the anchor
// itself lapsed, no-certs if no machine is certified, certs-exp if every cert
// for them has expired, otherwise ok.
func anchorStatus(a trust.Anchor, certs []proto.PeerCert, pubRaw []byte, now time.Time) string {
	if a.Expired(now) {
		return "EXPIRED"
	}
	var have, valid bool
	for _, c := range certs {
		if bytes.Equal(c.PersonKey, pubRaw) {
			have = true
			if now.Before(c.ValidUntil) {
				valid = true
			}
		}
	}
	switch {
	case valid:
		return "ok"
	case have:
		return "certs-exp"
	default:
		return "no-certs"
	}
}

func trustExport(args []string) error {
	fs := flag.NewFlagSet("trust export", flag.ExitOnError)
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
		return fmt.Errorf("no person identity — run `swarmctl identity init` first: %w", err)
	}
	label := ""
	if data, err := os.ReadFile(labelPath(cfg.TrustPersonKeyFile())); err == nil {
		label = string(bytes.TrimSpace(data))
	}
	certs, err := trust.LoadCerts(issuedCertsPath(cfg.TrustPersonKeyFile()))
	if err != nil {
		return err
	}
	b := trust.Bundle{
		Person:         label,
		Label:          label,
		IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Certs:          certs,
	}
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func trustImport(args []string) error {
	fs := flag.NewFlagSet("trust import", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	as := fs.String("as", "", "local person name (default: bundle's label)")
	weight := fs.Float64("weight", 0, "trust weight (default: config anchor_weight)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl trust import FILE [--as NAME] [--weight W]")
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var b trust.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}
	pub, err := identity.DecodePub(b.IdentityPubkey)
	if err != nil {
		return err
	}

	person := *as
	if person == "" {
		person = b.Person
	}
	if person == "" {
		return fmt.Errorf("bundle has no person name — pass --as NAME")
	}
	w := *weight
	if w == 0 {
		w = cfg.Trust.AnchorWeight
	}
	if w <= 0 || w > 1 {
		return fmt.Errorf("weight %v out of range (0,1]", w)
	}

	fmt.Println("identity:   ", b.IdentityPubkey)
	fmt.Println("fingerprint:", identity.Fingerprint(pub))
	fmt.Println("→ verify this fingerprint with", person, "over a channel you already trust")

	// Verify and merge the bundled certs into the local imported-cert cache.
	existing, err := trust.LoadCerts(cfg.TrustCertsFile())
	if err != nil {
		return err
	}
	byPeer := map[string]int{}
	for i, c := range existing {
		byPeer[c.PeerID] = i
	}
	imported := 0
	for _, c := range b.Certs {
		if !bytes.Equal(c.PersonKey, pub) {
			fmt.Fprintf(os.Stderr, "skipping cert for %s: signed by a different identity\n", c.PeerID)
			continue
		}
		if err := identity.VerifyCert(c, time.Now()); err != nil {
			fmt.Fprintf(os.Stderr, "skipping cert for %s: %v\n", c.PeerID, err)
			continue
		}
		if i, ok := byPeer[c.PeerID]; ok {
			existing[i] = c
		} else {
			existing = append(existing, c)
		}
		imported++
	}
	if err := trust.SaveCerts(cfg.TrustCertsFile(), existing); err != nil {
		return err
	}

	if err := upsertAnchor(cfg, trust.Anchor{
		Person:         person,
		Label:          b.Label,
		IdentityPubkey: b.IdentityPubkey,
		Weight:         w,
		Source:         "self-added",
	}); err != nil {
		return err
	}
	fmt.Printf("imported %d cert(s)\n", imported)
	return nil
}

func trustBlock(args []string) error {
	fset := flag.NewFlagSet("trust block", flag.ExitOnError)
	loadCfg := addConfigFlag(fset)
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl trust block PEER_ID")
	}
	peerID := fset.Arg(0)
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	path := cfg.TrustBlockedPeersFile()
	peers, err := trust.LoadBlockedPeers(path)
	if err != nil {
		return fmt.Errorf("load blocked peers: %w", err)
	}
	for _, p := range peers {
		if p == peerID {
			fmt.Printf("peer %s is already blocked\n", peerID)
			return nil
		}
	}
	peers = append(peers, peerID)
	if err := trust.SaveBlockedPeers(path, peers); err != nil {
		return fmt.Errorf("save blocked peers: %w", err)
	}
	fmt.Printf("blocked peer %s — swarmd will reload within 10s\n", peerID)
	return nil
}

func trustUnblock(args []string) error {
	fset := flag.NewFlagSet("trust unblock", flag.ExitOnError)
	loadCfg := addConfigFlag(fset)
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl trust unblock PEER_ID")
	}
	peerID := fset.Arg(0)
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	path := cfg.TrustBlockedPeersFile()
	peers, err := trust.LoadBlockedPeers(path)
	if err != nil {
		return fmt.Errorf("load blocked peers: %w", err)
	}
	filtered := peers[:0]
	for _, p := range peers {
		if p != peerID {
			filtered = append(filtered, p)
		}
	}
	if len(filtered) == len(peers) {
		fmt.Printf("peer %s was not in the blocked list\n", peerID)
		return nil
	}
	if err := trust.SaveBlockedPeers(path, filtered); err != nil {
		return fmt.Errorf("save blocked peers: %w", err)
	}
	fmt.Printf("unblocked peer %s — swarmd will reload within 10s\n", peerID)
	return nil
}

func upsertAnchor(cfg *config.Config, a trust.Anchor) error {
	anchors, err := trust.LoadAnchors(cfg.TrustAnchorsFile())
	if err != nil {
		return err
	}
	for i := range anchors {
		if anchors[i].Person == a.Person {
			anchors[i] = a
			if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), anchors); err != nil {
				return err
			}
			fmt.Printf("updated anchor %s (weight %.2f)\n", a.Person, a.Weight)
			return nil
		}
	}
	if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), append(anchors, a)); err != nil {
		return err
	}
	fmt.Printf("anchored %s (weight %.2f)\n", a.Person, a.Weight)
	return nil
}
