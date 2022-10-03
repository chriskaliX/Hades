package transport

import (
	"sync"

	"github.com/chriskaliX/SDK/transport/client"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/chriskaliX/SDK/transport/server"
	"go.uber.org/zap"
)

var _ IClient = (*client.Client)(nil)
var _ IServer = (*server.Server)(nil)

// Client-side interface
type IClient interface {
	SetSendHook(client.SendHookFunction)
	IsHooked() bool
	SendElkeid(*protocol.Record) error
	SendDebug(*protocol.Record) error
	SendRecord(*protocol.Record) error
	ReceiveTask() (*protocol.Task, error)
	Flush() error
	Close()
}

// Server-side interface
type IServer interface {
	GetState() (RxSpeed, TxSpeed, RxTPS, TxTPS float64)
	Receive(protocol.PoolGet, protocol.Trans)
	SendTask(protocol.Task) error

	Pid() int
	Name() string
	Wait() error
	Version() string
	IsExited() bool
	Shutdown()
	GetWorkingDirectory() string

	Wg() *sync.WaitGroup
	Logger() *zap.SugaredLogger
}
