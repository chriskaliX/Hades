package SDK

import (
	"github.com/chriskaliX/SDK/transport"
)

var _ ITransport = (*transport.Client)(nil)

type ITransport interface {
	SetSendHook(transport.SendHookFunction)
	SendElkeid(*transport.Record) error
	SendRecord(*transport.Record) error
	ReceiveTask() (*transport.Task, error)
	Flush() error
	Close()
}

// Unfinished
type ILogger interface {
	SetRemote(*transport.Client)
}
