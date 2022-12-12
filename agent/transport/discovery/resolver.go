// https://github.com/grpc/grpc-go/blob/v1.51.x/internal/resolver/dns/dns_resolver.go
// based on dns, replace the TXT part to http? Just a thought
package discovery

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/resolver"
)

var logger = grpclog.Component("hades")

var _ resolver.Resolver = (*Resolver)(nil)

var minDNSResRate = 30 * time.Second

// Resolver based on dns_resolver.go and watches for name resolution
// based on server's weight
type Resolver struct {
	host     string
	port     string
	resolver netResolver
	ctx      context.Context
	cancel   context.CancelFunc
	cc       resolver.ClientConn
	// rn channel is used by ResolveNow() to force an immediate resolution of the target.
	rn chan struct{}
	// wg is used to enforce Close() to return after the watcher() goroutine has finisher.
	// Otherwise, data race will be possible. [Race Example] in dns_resolver_test we
	// replace the real lookup functions with mocked ones to facilitate testing.
	// If Close() doesn't wait for watcher() goroutine finishes, race detector sometimes
	// will warns lookup (READ the lookup function pointers) inside watcher() goroutine
	// has data race with replaceNetFunc (WRITE the lookup function pointers).
	wg                   sync.WaitGroup
	disableServiceConfig bool
}

// Resolve immediately
func (r *Resolver) ResolveNow(resolver.ResolveNowOptions) {
	select {
	case r.rn <- struct{}{}:
	default:
	}
}

func (r *Resolver) Close() {
	r.cancel()
	r.wg.Wait()
}

func (r *Resolver) watcher() {
	defer r.wg.Done()
	backoffIndex := 1
	for {
		state, err := r.lookup()
		if err != nil {
			// Report error to the underlying grpc.ClientConn.
			r.cc.ReportError(err)
		} else {
			err = r.cc.UpdateState(*state)
		}

		var timer *time.Timer
		if err == nil {
			// Success resolving, wait for the next ResolveNow. However, also wait 30 seconds at the very least
			// to prevent constantly re-resolving.
			backoffIndex = 1
			timer = time.NewTimer(minDNSResRate)
			select {
			case <-r.ctx.Done():
				timer.Stop()
				return
			case <-r.rn:
			}
		} else {
			// backoffIndex
			// Poll on an error found in DNS Resolver or an error received from ClientConn.
			timer = time.NewTimer(DefaultExponential.Backoff(backoffIndex))
			backoffIndex++
		}
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (r *Resolver) lookup() (*resolver.State, error) {
	// srv, srvErr := r.lookupSRV()
	addrs, hostErr := r.lookupHost()
	// if hostErr != nil && (srvErr != nil || len(srv) == 0) {
	// 	return nil, hostErr
	// }
	if hostErr != nil {
		return nil, hostErr
	}

	state := resolver.State{Addresses: addrs}
	// if len(srv) > 0 {
	// 	state = grpclbstate.Set(state, &grpclbstate.State{BalancerAddresses: srv})
	// }
	// if !r.disableServiceConfig {
	// 	state.ServiceConfig = r.lookupTXT()
	// }
	return &state, nil
}

func (r *Resolver) lookupHost() ([]resolver.Address, error) {
	addrs, err := r.resolver.LookupHost(r.ctx, r.host)
	if err != nil {
		err = handleDNSError(err, "A")
		return nil, err
	}
	newAddrs := make([]resolver.Address, 0, len(addrs))
	for _, a := range addrs {
		ip, ok := formatIP(a)
		if !ok {
			return nil, fmt.Errorf("dns: error parsing A record IP address %v", a)
		}
		addr := ip + ":" + r.port
		newAddrs = append(newAddrs, resolver.Address{Addr: addr})
	}
	return newAddrs, nil
}

type netResolver interface {
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
	LookupTXT(ctx context.Context, name string) (txts []string, err error)
}

func handleDNSError(err error, lookupType string) error {
	if dnsErr, ok := err.(*net.DNSError); ok && !dnsErr.IsTimeout && !dnsErr.IsTemporary {
		// Timeouts and temporary errors should be communicated to gRPC to
		// attempt another DNS query (with backoff).  Other errors should be
		// suppressed (they may represent the absence of a TXT record).
		return nil
	}
	if err != nil {
		err = fmt.Errorf("dns: %v record lookup error: %v", lookupType, err)
		logger.Info(err)
	}
	return err
}

// formatIP returns ok = false if addr is not a valid textual representation of an IP address.
// If addr is an IPv4 address, return the addr and ok = true.
// If addr is an IPv6 address, return the addr enclosed in square brackets and ok = true.
func formatIP(addr string) (addrIP string, ok bool) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", false
	}
	if ip.To4() != nil {
		return addr, true
	}
	return "[" + addr + "]", true
}
