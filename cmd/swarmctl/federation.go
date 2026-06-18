package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JoeRu/swarmguard/internal/federation"
	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/trust"
)

// cmdFederation dispatches to federation sub-commands (spec §5.1 / §6.1).
func cmdFederation(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: swarmctl federation invite|join ...")
	}
	switch args[0] {
	case "invite":
		return federationInvite(args[1:])
	case "join":
		return federationJoin(args[1:])
	default:
		return fmt.Errorf("unknown federation subcommand %q", args[0])
	}
}

// federationInvite creates an invitation token that the local operator can
// hand to a peer who wants to join this federation.
func federationInvite(args []string) error {
	fset := flag.NewFlagSet("federation invite", flag.ExitOnError)
	loadCfg := addConfigFlag(fset)
	addr := fset.String("addr", "", "bare transport multiaddr, e.g. /ip4/1.2.3.4/tcp/7700 (required)")
	out := fset.String("out", "", "write invitation to FILE instead of stdout")
	if err := fset.Parse(args); err != nil {
		return err
	}

	if *addr == "" {
		return fmt.Errorf("--addr is required (e.g. --addr /ip4/1.2.3.4/tcp/7700)")
	}

	cfg, err := loadCfg()
	if err != nil {
		return err
	}

	labelData, err := os.ReadFile(labelPath(cfg.TrustPersonKeyFile()))
	if err != nil {
		return fmt.Errorf("no person identity (%w) — run `swarmctl setup` first", err)
	}
	label := strings.TrimSpace(string(labelData))

	inv, err := federation.NewInvitation(cfg, label, *addr)
	if err != nil {
		return fmt.Errorf("create invitation: %w", err)
	}

	// Compute fingerprint for the operator hint.
	personPriv, err := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		return err
	}
	pub := identity.PersonPub(personPriv)
	fp := identity.Fingerprint(pub)

	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return fmt.Errorf("create invitation file %s: %w", *out, err)
		}
		defer f.Close()
		if err := federation.WriteInvitation(f, inv); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "invitation written to %s\n", *out)
		fmt.Fprintf(os.Stderr, "→ send %s to the operator joining your federation\n", *out)
		fmt.Fprintf(os.Stderr, "→ ask them to verify fingerprint: %s\n", fp)
	} else {
		if err := federation.WriteInvitation(os.Stdout, inv); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "→ ask the recipient to verify fingerprint: %s\n", fp)
	}
	return nil
}

// federationJoin imports an invitation produced by the remote operator and
// anchors their identity locally, then prints the config snippet and
// reciprocal-export hint.
func federationJoin(args []string) error {
	fset := flag.NewFlagSet("federation join", flag.ExitOnError)
	loadCfg := addConfigFlag(fset)
	as := fset.String("as", "", "local person name (default: invitation's invited_by label)")
	weight := fset.Float64("weight", 0, "trust weight in (0,1] (default: invitation's suggested_weight or config anchor_weight)")
	if err := fset.Parse(args); err != nil {
		return err
	}

	if fset.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl federation join INVITE_FILE [--as NAME] [--weight W]")
	}
	invFile := fset.Arg(0)

	f, err := os.Open(invFile)
	if err != nil {
		return fmt.Errorf("open invitation file %s: %w", invFile, err)
	}
	defer f.Close()

	inv, err := federation.ReadInvitation(f)
	if err != nil {
		return fmt.Errorf("read invitation %s: %w", fset.Arg(0), err)
	}

	cfg, err := loadCfg()
	if err != nil {
		return err
	}

	// Show invitation summary.
	fmt.Printf("Invitation from: %s\n", inv.InvitedBy)
	fmt.Printf("Bootstrap peer:  %s\n", inv.Federation.BootstrapPeer)
	fmt.Printf("Federation mode: %s\n", inv.Federation.Mode)
	fmt.Println()

	// Decode the inviting person's public key and compute fingerprint.
	pub, err := identity.DecodePub(inv.Trust.IdentityPubkey)
	if err != nil {
		return fmt.Errorf("decode identity pubkey: %w", err)
	}
	fp := identity.Fingerprint(pub)

	fmt.Printf("Fingerprint: %s\n", fp)
	fmt.Printf("Verify this with %s over a channel you already trust, then type 'yes' to continue: ", inv.InvitedBy)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.TrimSpace(scanner.Text())
	if answer != "yes" {
		fmt.Println("aborted — import nothing.")
		return nil
	}

	// Resolve person name.
	person := *as
	if person == "" {
		person = inv.InvitedBy
	}
	if person == "" {
		return fmt.Errorf("bundle has no person name — pass --as NAME")
	}

	// Resolve weight.
	w := *weight
	if w == 0 && inv.Federation.SuggestedWeight > 0 {
		w = inv.Federation.SuggestedWeight
	}
	if w == 0 {
		w = cfg.Trust.AnchorWeight
	}
	if w <= 0 || w > 1 {
		return fmt.Errorf("weight %v out of range (0,1]", w)
	}

	// Import certs.
	existing, err := trust.LoadCerts(cfg.TrustCertsFile())
	if err != nil {
		return fmt.Errorf("load certs: %w", err)
	}
	byPeer := map[string]int{}
	for i, c := range existing {
		byPeer[c.PeerID] = i
	}
	imported := 0
	for _, c := range inv.Trust.Certs {
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
		return fmt.Errorf("save certs: %w", err)
	}

	// Anchor the inviting person.
	if err := upsertAnchor(cfg, trust.Anchor{
		Person:         person,
		Label:          inv.Trust.Label,
		IdentityPubkey: inv.Trust.IdentityPubkey,
		Weight:         w,
		Source:         "federation-join",
	}); err != nil {
		return err
	}

	fmt.Printf("✓ anchored %s (weight %.2f)\n", person, w)
	fmt.Printf("✓ imported %d cert(s)\n", imported)

	// Print config snippet.
	fmt.Printf("\nAdd to your config.yaml:\n")
	fmt.Println("──────────────────────────────────────────")
	fmt.Printf("  federation_mode: %s\n", inv.Federation.Mode)
	fmt.Printf("  bootstrap_peers:\n")
	fmt.Printf("    - %s\n", inv.Federation.BootstrapPeer)
	fmt.Println("──────────────────────────────────────────")

	// Print reciprocal export hint.
	fmt.Printf("\nNow send your bundle so they can anchor you back:\n")
	fmt.Printf("  swarmctl trust export > my.bundle\n")
	fmt.Printf("  # send my.bundle to %s\n", person)
	fmt.Printf("  # they run: swarmctl trust import my.bundle --as bob --weight 0.8\n")

	return nil
}
