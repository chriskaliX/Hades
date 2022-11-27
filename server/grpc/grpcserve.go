package grpc

import (
	"hboat/grpc/transfer"
	"hboat/grpc/transfer/conf"
)

func RunWrapper(enableCA bool, addr string, port int) {
	transfer.RunServer(enableCA, addr, port, conf.ServerCert, conf.ServerKey, conf.CaCert)
}
