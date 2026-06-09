package enforce

// ipset backend — O(1) hash sets via netlink. The correct default; NOT a rule
// per IP (that would be O(n) per packet, spec §11.3, problem Q). Stub.
