// Package transport is the libp2p layer: gossipsub (control plane) +
// Kademlia DHT (on-demand peer/score lookup) + relay role (spec §5, §11).
//
// Node is the main type. Relay nodes run DHT server mode and circuit relay v2;
// leaf nodes are standard clients. See docs/spec.md §11.4 and
// docs/superpowers/specs/2026-06-09-p2p-transport-skeleton-design.md.
package transport
