module github.com/JoeRu/swarmguard

go 1.22

// Dependencies are added as implementation progresses. Expected core deps:
//   github.com/libp2p/go-libp2p          // P2P transport: gossipsub + kademlia DHT
//   github.com/dgraph-io/badger/v4       // embedded reputation store (TTL → decay GC)
//   github.com/bits-and-blooms/bloom/v3  // compact negative pre-filter
//   gopkg.in/yaml.v3                      // config
