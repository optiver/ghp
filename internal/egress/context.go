package egress

import (
	"context"
	"net/netip"
)

type clientIPKey struct{}

// WithClientIP carries a trusted, canonical IP without a source port. Invalid
// or absent addresses use round robin when the configured strategy is IP hash.
func WithClientIP(ctx context.Context, ip string) context.Context {
	addr, err := netip.ParseAddr(ip)
	key := ""
	if err == nil {
		key = addr.Unmap().WithZone("").String()
	}
	return context.WithValue(ctx, clientIPKey{}, key)
}

// Background retains only immutable routing metadata, without inheriting
// request cancellation or mutable access-log slots. Callers supply a timeout.
func Background(ctx context.Context) context.Context {
	key, _ := ctx.Value(clientIPKey{}).(string)
	return context.WithValue(context.Background(), clientIPKey{}, key)
}
