// Service discovery is under development
// study for now
package discovery

import (
	"context"

	"google.golang.org/grpc/resolver"
)

type ResolverBuilder struct{}

func (r *ResolverBuilder) Scheme() string { return "hades" }

func (r *ResolverBuilder) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	// host, port, err := parseTarget(target.Endpoint, defaultPort)
	// if err != nil {
	// 	return nil, err
	// }

	// // IP address.
	// if ipAddr, ok := formatIP(host); ok {
	// 	addr := []resolver.Address{{Addr: ipAddr + ":" + port}}
	// 	cc.UpdateState(resolver.State{Addresses: addr})
	// 	return deadResolver{}, nil
	// }

	// DNS address (non-IP).
	ctx, cancel := context.WithCancel(context.Background())
	resolver := &Resolver{
		// host:                 host,
		// port:                 port,
		ctx:                  ctx,
		cancel:               cancel,
		cc:                   cc,
		rn:                   make(chan struct{}, 1),
		disableServiceConfig: opts.DisableServiceConfig,
	}

	// if target.Authority == "" {
	// 	d.resolver = defaultResolver
	// } else {
	// 	d.resolver, err = customAuthorityResolver(target.Authority)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	resolver.wg.Add(1)
	go resolver.watcher()
	return resolver, nil
}

// deadResolver is a resolver that does nothing.
type deadResolver struct{}

func (deadResolver) ResolveNow(resolver.ResolveNowOptions) {}

func (deadResolver) Close() {}
