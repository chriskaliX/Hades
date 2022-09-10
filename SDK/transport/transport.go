package transport

import (
	"github.com/chriskaliX/SDK/transport/client"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/chriskaliX/SDK/transport/server"
)

var _ IClient = (*client.Client)(nil)
var _ IServer = (*server.Server)(nil)

type IClient interface {
	SetSendHook(client.SendHookFunction)
	SendElkeid(*protocol.Record) error
	SendDebug(*protocol.Record) error
	SendRecord(*protocol.Record) error
	ReceiveTask() (*protocol.Task, error)
	Flush() error
	Close()
}

type IServer interface {
	GetState() (RxSpeed, TxSpeed, RxTPS, TxTPS float64)
	Receive(rec *protocol.Record) error
	SendTask(protocol.Task) error

	Pid() int
	Name() string
	Wait() error
	Version() string
	IsExited() bool
	GetWorkingDirectory() string
}
