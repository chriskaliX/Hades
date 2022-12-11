package discovery

import (
	"google.golang.org/grpc/resolver"
)

var _ resolver.Resolver = (*Resolver)(nil)

type Resolver struct{}

func (r *Resolver) ResolveNow(resolver.ResolveNowOptions) {}

func (r *Resolver) Close() {}
