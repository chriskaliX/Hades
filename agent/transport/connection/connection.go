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
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/xds"
)

// Grpc address
var GrpcAddr string
var InsecureTransport bool
var InsecureTLS bool

var DefaultConn *Connection

var _ connection.INetRetry = (*Connection)(nil)

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
			grpc.WithBlock(),
			grpc.FailOnNonTempDialError(true),
			// grpc.WithConnectParams(),
			grpc.WithStatsHandler(&DefaultStatsHandler),
			// grpc.WithResolvers(),
		},
		Addr: GrpcAddr,
	}
	zap.S().Infof("grpc addr: %s, insecure: %v, insecure-tls: %v", gConn.Addr, InsecureTransport, InsecureTLS)
	// insecure transport, for debug
	if InsecureTransport {
		gConn.Options = append(gConn.Options, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		gConn.Options = append(gConn.Options, grpc.WithTransportCredentials(credentials.NewTLS(LoadTLSConfig("hades.com"))))
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	g.Conn, err = grpc.DialContext(ctx, g.Addr, g.Options...)
	return
}
