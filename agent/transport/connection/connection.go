package connection

/*
	grpc 连接
*/

import (
	"agent/network"
	"crypto/tls"
	"crypto/x509"
	"reflect"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	dialOptions = []grpc.DialOption{}
	addr        = "test.hades.net"
)

func New() (*grpc.ClientConn, error) {
	grpcConn := &network.Context{}
	grpcInstance := &Grpc{}
	err := grpcConn.IRetry(grpcInstance)
	if err != nil {
		return nil, err
	}
	return grpcInstance.Conn, nil
}

func setDialOptions(ca, privkey, cert []byte, svrName string) {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca)
	keyPair, _ := tls.X509KeyPair(cert, privkey)
	dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{keyPair},
		ServerName:   svrName,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs:      certPool,
	})), grpc.WithBlock(), grpc.WithTimeout(time.Second*2))
}

type Grpc struct {
	Addr    string
	Options []grpc.DialOption
	Conn    *grpc.ClientConn
}

func (g *Grpc) String() string {
	return reflect.TypeOf(g).String()
}

func (g *Grpc) GetMaxRetry() uint {
	return 3
}

func (g *Grpc) GetHashMod() uint {
	return 1
}

func (g *Grpc) Close() {
	if g != nil {
		g.Conn.Close()
	}
}

func (g *Grpc) Connect() error {
	conn, err := grpc.Dial(g.Addr, g.Options...)
	if err != nil {
		return err
	}
	g.Conn = conn
	return nil
}

func (g *Grpc) Init() error {
	return nil
}
