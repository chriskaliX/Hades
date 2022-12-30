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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/chriskaliX/SDK/utils/connection"
	"go.uber.org/zap"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Grpc address
var GrpcAddr string
var InsecureTransport bool
var InsecureTLS bool

var DefaultConn = New()

// Get the connection from gRPCConn
func GetConnection(ctx context.Context) (conn *grpc.ClientConn, err error) {
	var ok bool
	conn, ok = DefaultConn.Conn.Load().(*grpc.ClientConn)
	if ok {
		// Connection pre check
		switch conn.GetState() {
		case connectivity.Idle:
			// connect
		case connectivity.Connecting, connectivity.TransientFailure:
			conn.Close()
		case connectivity.Ready:
			return conn, nil
		}
	}
	if err = connection.IRetry(ctx, DefaultConn); err != nil {
		return nil, err
	}
	return conn, nil
}

var _ connection.INetRetry = (*Connection)(nil)

type Connection struct {
	Addr    string
	Options []grpc.DialOption
	Conn    atomic.Value
	NetMode atomic.Value
}

func New() *Connection {
	conn := &Connection{
		Options: []grpc.DialOption{
			grpc.WithBlock(),
			grpc.FailOnNonTempDialError(true),
			grpc.WithStatsHandler(&DefaultStatsHandler),
		},
		Addr: GrpcAddr,
	}
	zap.S().Infof("grpc addr: %s, insecure: %v, insecure-tls: %v", conn.Addr, InsecureTransport, InsecureTLS)
	// insecure transport, for debug
	var cred credentials.TransportCredentials
	if InsecureTransport {
		cred = insecure.NewCredentials()
	} else {
		cred = credentials.NewTLS(conn.loadTLSConfig("hades.com"))
	}
	conn.Options = append(conn.Options, grpc.WithTransportCredentials(cred))
	return conn
}

// INetRetry Impls
func (c *Connection) String() string { return "grpc" }

func (c *Connection) GetMaxDelay() uint { return 120 }

// Retry forever, in case server shutdown or networking fluctuation
// makes all agent shutdown
func (c *Connection) GetMaxRetry() uint { return 0 }

func (c *Connection) GetInterval() uint { return 3 }

func (c *Connection) GetHashMod() uint { return uint(rand.Intn(10)) }

// TODO: A look-aside LB is needed, for now, only server-side, dns
func (c *Connection) Connect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, c.Addr, c.Options...)
	if err != nil {
		return err
	}
	c.Conn.Store(conn)
	return nil
}

func (g *Connection) loadTLSConfig(host string) *tls.Config {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(CaCert)
	keyPair, _ := tls.X509KeyPair(ClientCert, ClientKey)
	return &tls.Config{
		// Elkeid has removed ServerName while InsecureSkipVerify is introduced.
		// ServerName: host,
		// Skip the verification step, by useing the VerifyPeerCertificate. In
		// production environment, use `InsecureSkipVerify` with combination
		// with `VerifyConnection` or `VerifyPeerCertificate`
		//
		// In Elkeid, InsecureSkipVerify is always true.
		InsecureSkipVerify: InsecureTLS,
		RootCAs:            certPool,
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{keyPair},
		// Enforce the client cerificate during the handshake (server related)
		// This is different with kolide/launcher since cert is always required
		// in Elkeid/Hades.
		ClientAuth: tls.RequireAndVerifyClientCert,
		// Verify certificate by function, avoid MITM
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			zap.S().Info("grpc tls verify cert start")
			certs := make([]*x509.Certificate, len(rawCerts))
			// Totally by Elkeid, have not checked yet
			// get asn1 data from the server certs
			for i, asn1Data := range rawCerts {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return errors.New("tls: failed to parse certificate from server: " + err.Error())
				}
				certs[i] = cert
			}
			opts := x509.VerifyOptions{
				Roots:         certPool,
				DNSName:       host,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := certs[0].Verify(opts)
			if err != nil {
				zap.S().Errorln(err)
			}
			return err
		},
	}
}
