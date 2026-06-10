package reputation

// decay implements asymmetric reputation decay: trust rises slowly, falls fast;
// IP scores decay toward zero without fresh corroboration, which doubles as the
// GDPR storage-limitation mechanism (spec §4.3, §8, §9). Stub.
