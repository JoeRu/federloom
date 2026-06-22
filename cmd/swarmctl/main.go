// Command swarmctl is the SwarmGuard admin CLI: node identity, Person
// identities, peer-certs, and the local trust-anchor list (spec §5.1).
package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprint(os.Stderr, `swarmctl — SwarmGuard admin CLI

Flags must come BEFORE positional args (PERSON, PEER_ID, FILE).

Usage:
  swarmctl setup [--label NAME]
  swarmctl status
  swarmctl federation invite --addr MULTIADDR [--weight W] [--out FILE]
  swarmctl federation join FILE [--as NAME] [--weight W]
  swarmctl identity                      print this node's peer ID
  swarmctl identity init --label NAME    create a Person identity + self peer-cert
  swarmctl identity show                 print Person pubkey + fingerprint
  swarmctl peer-cert PEER_ID             sign a peer-cert for another machine
  swarmctl trust add --identity ed25519:... [--weight W] [--label L] PERSON
  swarmctl trust set [--weight W] [--label L] PERSON
  swarmctl trust remove PERSON
  swarmctl trust list
  swarmctl trust export                  write this Person's bundle to stdout
  swarmctl trust import [--as NAME] [--weight W] FILE
  swarmctl trust block PEER_ID
  swarmctl trust unblock PEER_ID
  swarmctl whitelist add [--scope local-only] [--source manual] IP_OR_CIDR
  swarmctl whitelist remove IP_OR_CIDR
  swarmctl whitelist list

All commands accept -config PATH (same file swarmd uses).
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
		fmt.Fprintln(os.Stderr, "swarmctl:", err)
		os.Exit(1)
	}
}
