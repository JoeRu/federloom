package transport

import "github.com/libp2p/go-libp2p"

// buildLibp2pOptions translates Options into libp2p functional options.
func buildLibp2pOptions(opts Options) []libp2p.Option {
	var lo []libp2p.Option

	if len(opts.ListenAddrs) > 0 {
		lo = append(lo, libp2p.ListenAddrs(opts.ListenAddrs...))
	}

	if opts.PrivKey != nil {
		lo = append(lo, libp2p.Identity(opts.PrivKey))
	}

	if opts.Mode == ModeRelay {
		lo = append(lo, libp2p.EnableRelayService())
	}

	return lo
}
