package transfer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	_ "hboat/grpc/transfer/compressor"
	"hboat/grpc/transfer/handler"
	pb "hboat/grpc/transfer/proto"
)

const (
	// If the client pings the server multiple times within MinPingTIme time,
	// the connection will be terminated
	defaultMinPingTime = 5 * time.Second

	// Maximum connection idle time
	defaultMaxConnIdle = 20 * time.Minute

	//If the connection is idle during pingtime,
	//the server takes the initiative to ping http_client
	defaultPingTime = 10 * time.Minute

	//Same as above, the timeout period of server waiting for ack when pinging client
	defaultPingAckTimeout = 5 * time.Second

	maxMsgSize = 1024 * 1024 * 10 // grpc maximum message size:10M
)

// Get the encryption certificate
func credential(crtFile, keyFile, caBytes []byte) credentials.TransportCredentials {
	cert, err := tls.X509KeyPair(crtFile, keyFile)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caBytes); !ok {
		return nil
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	})
}

func RunServer(enableCA bool, addr string, port int, crtFile, keyFile, caFile []byte) {
	log.SetPrefix("Hboat grpc ")
	// Handling client timeout
	kaep := keepalive.EnforcementPolicy{
		MinTime:             defaultMinPingTime,
		PermitWithoutStream: true,
	}

	kasp := keepalive.ServerParameters{
		MaxConnectionIdle: defaultMaxConnIdle,
		Time:              defaultPingTime,
		Timeout:           defaultPingAckTimeout,
	}

	opts := []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(kaep),
		grpc.KeepaliveParams(kasp),

		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
	}

	if enableCA {
		ct := credential(crtFile, keyFile, caFile)
		if ct == nil {
			os.Exit(-1)
		}
		opts = append(opts, grpc.Creds(ct))
	}

	server := grpc.NewServer(opts...)
	pb.RegisterTransferServer(server, &handler.TransferHandler{})
	reflection.Register(server)
	lis, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		log.Printf("tcp error: %v\n", err)
		os.Exit(-1)
	}

	log.Printf("tcp listen OK: %v, CA: %v\n", lis.Addr().String(), enableCA)
	if err = server.Serve(lis); err != nil {
		log.Printf("listen error: %v\n", err)
		os.Exit(-1)
	}
}
