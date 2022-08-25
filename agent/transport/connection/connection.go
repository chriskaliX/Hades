package connection

import (
	"agent/network"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var DebugAddr string
var DebugPort string
var EnableCA bool

var _ network.INetRetry = (*Grpc)(nil)

// Grpc instance for establish connection with server
type Grpc struct {
	Addr    string
	Options []grpc.DialOption
	Conn    *grpc.ClientConn
}

func New(ctx context.Context) (*grpc.ClientConn, error) {
	grpcInstance := &Grpc{}
	grpcInstance.init()
	err := network.IRetry(grpcInstance, ctx)
	if err != nil {
		return nil, err
	}
	return grpcInstance.Conn, nil
}

func (g *Grpc) String() string {
	return "grpc"
}

func (g *Grpc) GetMaxDelay() uint {
	return 600
}

func (g *Grpc) GetMaxRetry() uint {
	return 0
}

func (g *Grpc) GetInterval() uint {
	return 5
}

func (g *Grpc) GetHashMod() uint {
	return uint(rand.Intn(10))
}

func (g *Grpc) Connect() (err error) {
	if err := g.init(); err != nil {
		return err
	}
	g.Conn, err = grpc.Dial(g.Addr, g.Options...)
	return nil
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
