package transport

import (
	"context"

	"github.com/libp2p/go-libp2p/core/host"
	dht "github.com/libp2p/go-libp2p-kad-dht"
)

func buildDHT(ctx context.Context, h host.Host, mode NodeMode) (*dht.IpfsDHT, error) {
	if mode == ModeRelay {
		return dht.New(ctx, h, dht.Mode(dht.ModeServer))
	}
	return dht.New(ctx, h, dht.Mode(dht.ModeClient))
}
