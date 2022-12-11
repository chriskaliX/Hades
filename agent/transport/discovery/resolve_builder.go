// Service discovery is under development
package discovery

import (
	"google.golang.org/grpc/resolver"
)

type ResolverBuilder struct{}

func (r *ResolverBuilder) Scheme() string { return "hades" }

func (r *ResolverBuilder) Build(target resolver.Target, cc resolver.ClientConn, _ resolver.BuildOptions) (resolver.Resolver, error) {
	return nil, nil
}
