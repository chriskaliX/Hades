// Connection
//
// The Connection is now working by gRPC for communicating with server.
//
// Connection will temporary stay in directory agent instead of SDC since
// agent should be this only process to communicate with the server.
// In Osquery(kolide), only hostname is specific in compile time. The
// reference is here:
// https://github.com/kolide/launcher/blob/main/pkg/service/client_grpc.go#L102
//
// For high performance requirements(low latency, high traffic), a look-aside
// load balancing is required just like Elkeid agent does.
// The client-side LB using grpc-LB protocol. There are 3 of the protocols.
//
// 1. pick_first (Elkeid way)
// 2. round_robin
// 3. grpclb(dropped, xDS instead)
//
// The xDS(x Discovery Service) with it's recommanded docs here:
// https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol
// APIs:
// - Listener Discovery Service(LDS)
// - Route Discovery Service (RDS)
// - Cluster Discovery Service (CDS)
// - Endpoint Discovery Service (EDS)
// - Aggregate Discovery Service (ADS) (coming soon)
//
// References:
// https://grpc.io/blog/grpc-load-balancing/
// https://github.com/grpc/grpc/blob/master/doc/load-balancing.md
package connection

import (
	"context"
	"math/rand"
	"time"

	"github.com/chriskaliX/SDK/util/connection"
	"go.uber.org/atomic"
	"go.uber.org/zap"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/xds"
)

// Grpc address
var GrpcAddr string
var InsecureTransport bool
var InsecureTLS bool

var GRPCConnection *Connection

var _ connection.INetRetry = (*Connection)(nil)

// Grpc instance for establish connection with server in a load-balanced way
//
// In Elkeid, there is 3 ways of connection.
//  1. service discovery
//     It is done by the server (registry/detail). Client side query the
//     service discovery host by look up the os env, and this is the reason
//     that a setting-env operation is used in Elkeid in Task.
//  2. private network
//     private network addr, same with service discovery by env looking up.
//  3. public network
//     same way
//
// The os.Setenv way to cache the variables is also working in Windows.
// Compatibility is not concerned for now.
type Connection struct {
	Addr     string
	Options  []grpc.DialOption
	Conn     *grpc.ClientConn
	NetMode  atomic.String // to specific the network mode, just like Elkeid
	Protocol atomic.String // xDS future
}

// Get the connection from gRPCConn
func GetConnection(g *Connection, ctx context.Context) (conn *grpc.ClientConn, err error) {
	if err = connection.IRetry(g, ctx); err != nil {
		return nil, err
	}
	return g.Conn, nil
}

func New() *Connection {
	gConn := &Connection{
		Options: []grpc.DialOption{
			// Disable retry, which does not impact to transparent retry.
			// Just let the IRetry to take over this
			// grpc.WithDisableRetry(),
			// Get connection failed details
			grpc.WithReturnConnectionError(),
			// FailOnNonTempDialError is an EXPERIMENTAL option for grpc
			// connection and it uses with WithBlock. The PR is here
			// https://github.com/grpc/grpc-go/pull/985
			//
			// Without the FailOnNonTempDialError, client will not retry
			// for a temporary error like server restarts. For purpose of
			// retrying, WithDisableRetry may should be moved since gRPC
			// connection is a special case.
			grpc.WithBlock(),
			grpc.FailOnNonTempDialError(true),
			// Default timeout set, TODO: with context
			grpc.WithTimeout(time.Second * 3),
		},
		Addr: GrpcAddr,
	}
	zap.S().Infof("grpc addr: %s, insecure: %v, insecure-tls: %v", gConn.Addr, InsecureTransport, InsecureTLS)
	// insecure transport, for debug
	if InsecureTransport {
		gConn.Options = append(gConn.Options, grpc.WithInsecure())
	} else {
		gConn.Options = append(gConn.Options,
			grpc.WithTransportCredentials(credentials.NewTLS(LoadTLSConfig("hades.com"))),
		)
	}
	return gConn
}

// INetRetry Impls
func (g *Connection) String() string {
	return "grpc"
}

func (g *Connection) GetMaxDelay() uint {
	return 120
}

// Retry forever, in case server shutdown or networking fluctuation
// makes all agent shutdown
func (g *Connection) GetMaxRetry() uint {
	return 0
}

func (g *Connection) GetInterval() uint {
	return 3
}

func (g *Connection) GetHashMod() uint {
	return uint(rand.Intn(10))
}

// TODO: A look-aside LB is needed, for now, only server-side, dns
func (g *Connection) Connect() (err error) {
	g.Conn, err = grpc.Dial(g.Addr, g.Options...)
	return
}
