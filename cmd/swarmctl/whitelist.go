package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

func cmdWhitelist(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: swarmctl whitelist add|remove|list ...")
	}
	switch args[0] {
	case "add":
		return whitelistAdd(args[1:])
	case "remove":
		return whitelistRemove(args[1:])
	case "list":
		return whitelistList(args[1:])
	default:
		return fmt.Errorf("unknown whitelist subcommand %q; use add, remove, or list", args[0])
	}
}

func whitelistAdd(args []string) error {
	fs := flag.NewFlagSet("whitelist add", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	scope := fs.String("scope", "local-only", `scope: "local-only" or "shared-vote"`)
	source := fs.String("source", "manual", `source: "manual", "install-script", or "federation"`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl whitelist add [--scope local-only] IP_OR_CIDR")
	}
	ipOrRange := fs.Arg(0)
	if net.ParseIP(ipOrRange) == nil {
		if _, _, err := net.ParseCIDR(ipOrRange); err != nil {
			return fmt.Errorf("invalid IP or CIDR %q: %w", ipOrRange, err)
		}
	}
	if *scope != "local-only" && *scope != "shared-vote" {
		return fmt.Errorf("scope must be \"local-only\" or \"shared-vote\"")
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		return fmt.Errorf("load whitelist: %w", err)
	}
	before := len(wl.List())
	if err := wl.Add(proto.WhitelistEntry{
		IPOrRange: ipOrRange,
		Scope:     *scope,
		Source:    *source,
	}); err != nil {
		return fmt.Errorf("add to whitelist: %w", err)
	}
	if len(wl.List()) > before {
		fmt.Printf("added %s (scope: %s) — restart swarmd to activate\n", ipOrRange, *scope)
	} else {
		fmt.Printf("%s already in whitelist (no change)\n", ipOrRange)
	}
	return nil
}

func whitelistRemove(args []string) error {
	fs := flag.NewFlagSet("whitelist remove", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl whitelist remove IP_OR_CIDR")
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		return fmt.Errorf("load whitelist: %w", err)
	}
	if err := wl.Remove(fs.Arg(0)); err != nil {
		return fmt.Errorf("remove from whitelist: %w", err)
	}
	fmt.Printf("removed %s — restart swarmd to activate\n", fs.Arg(0))
	return nil
}

func whitelistList(args []string) error {
	fs := flag.NewFlagSet("whitelist list", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		return fmt.Errorf("load whitelist: %w", err)
	}
	entries := wl.List()
	if len(entries) == 0 {
		fmt.Println("no whitelist entries — see `swarmctl whitelist add`")
		return nil
	}
	fmt.Printf("%-40s %-12s %s\n", "IP/CIDR", "SCOPE", "SOURCE")
	for _, e := range entries {
		fmt.Printf("%-40s %-12s %s\n", e.IPOrRange, e.Scope, e.Source)
	}
	return nil
}
