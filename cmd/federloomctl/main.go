// Command federloomctl is the FederLoom admin CLI: node identity, Person
// identities, peer-certs, and the local trust-anchor list (spec §5.1).
package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprint(os.Stderr, `federloomctl — FederLoom admin CLI

Flags must come BEFORE positional args (PERSON, PEER_ID, FILE).

Usage:
  federloomctl setup [--label NAME]
  federloomctl status
  federloomctl federation invite --addr MULTIADDR [--weight W] [--out FILE]
  federloomctl federation join FILE [--as NAME] [--weight W]
  federloomctl identity                      print this node's peer ID
  federloomctl identity init --label NAME    create a Person identity + self peer-cert
  federloomctl identity show                 print Person pubkey + fingerprint
  federloomctl peer-cert PEER_ID             sign a peer-cert for another machine
  federloomctl trust add --identity ed25519:... [--weight W] [--label L] PERSON
  federloomctl trust set [--weight W] [--label L] PERSON
  federloomctl trust remove PERSON
  federloomctl trust list
  federloomctl trust export                  write this Person's bundle to stdout
  federloomctl trust import [--as NAME] [--weight W] FILE
  federloomctl trust block PEER_ID
  federloomctl trust unblock PEER_ID
  federloomctl whitelist add [--scope local-only] [--source manual] IP_OR_CIDR
  federloomctl whitelist remove IP_OR_CIDR
  federloomctl whitelist list

All commands accept -config PATH (same file federloomd uses).
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "federation":
		err = cmdFederation(os.Args[2:])
	case "identity":
		err = cmdIdentity(os.Args[2:])
	case "peer-cert":
		err = cmdPeerCert(os.Args[2:])
	case "trust":
		err = cmdTrust(os.Args[2:])
	case "whitelist":
		err = cmdWhitelist(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "federloomctl:", err)
		os.Exit(1)
	}
}
