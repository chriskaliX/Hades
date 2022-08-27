package SDK

import (
	"time"

	"github.com/chriskaliX/SDK/clock"
	"github.com/chriskaliX/SDK/transport"
)

var _ ITransport = (*transport.Client)(nil)
var _ IClock = (*clock.Clock)(nil)

type ITransport interface {
	SetSendHook(transport.SendHookFunction)
	SendElkeid(*transport.Record) error
	SendRecord(*transport.Record) error
	ReceiveTask() (*transport.Task, error)
	Flush() error
	Close()
}

type IClock interface {
	Now() time.Time
	Reset(time.Duration)
	Close()
}

// Unfinished
// Refactory?
type ILogger interface {
	SetRemote(*transport.Client)
}
