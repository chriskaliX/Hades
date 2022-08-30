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
// Other References:
//
// https://grpc.io/blog/grpc-load-balancing/
// https://github.com/grpc/grpc/blob/master/doc/load-balancing.md
package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"time"

	"github.com/chriskaliX/SDK/util/connection"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var DebugAddr string
var DebugPort string
var EnableCA bool

var _ connection.INetRetry = (*Grpc)(nil)

// Grpc instance for establish connection with server in a load-balanced way
//
// In Elkeid, there is 3 ways of connection.
// 1. service discovery
//    It is done by the server (registry/detail). Client side query the
// 	  service discovery host by look up the os env, and this is the reason
//    that a setting-env operation is used in Elkeid in Task.
// 2. private network
//    private network addr, same with service discovery by env looking up.
// 3. public network
//    same way
//
// The os.Setenv way to cache the variables is also working in Windows.
// Compatibility is not concerned for now.
type Grpc struct {
	Addr    string
	Options []grpc.DialOption
	Conn    *grpc.ClientConn
	NetMode string // to specific the network mode, just like Elkeid
}

func New(ctx context.Context) (*grpc.ClientConn, error) {
	grpcInstance := &Grpc{}
	grpcInstance.init()
	err := connection.IRetry(grpcInstance, ctx)
	if err != nil {
		return nil, err
	}
	return grpcInstance.Conn, nil
}

// INetRetry Impls
func (g *Grpc) String() string {
	return "grpc"
}

func (g *Grpc) GetMaxDelay() uint {
	return 120
}

func (g *Grpc) GetMaxRetry() uint {
	return 5
}

func (g *Grpc) GetInterval() uint {
	return 5
}

func (g *Grpc) GetHashMod() uint {
	return uint(rand.Intn(10))
}

func (g *Grpc) Connect() (err error) {
	if err = g.init(); err != nil {
		return err
	}
	g.Conn, err = grpc.Dial(g.Addr, g.Options...)
	return
}

func (g *Grpc) EnableCA(ca, privkey, cert []byte, svrName string) {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca)
	keyPair, _ := tls.X509KeyPair(cert, privkey)
	g.Options = append(g.Options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{keyPair},
		ServerName:   svrName,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs:      certPool,
	})), grpc.WithBlock(), grpc.WithTimeout(time.Second*3))
}

func (g *Grpc) DisableCA() {
	g.Options = append(g.Options, grpc.WithInsecure())
}

func (g *Grpc) init() error {
	if EnableCA {
		g.EnableCA(CaCert, ClientKey, ClientCert, "hades.com")
	} else {
		g.DisableCA()
	}
	// Disable retry, let IRetry do the work
	g.Options = append(g.Options, grpc.WithDisableRetry())
	g.Addr = fmt.Sprintf("%s:%s", DebugAddr, DebugPort)
	return nil
}
