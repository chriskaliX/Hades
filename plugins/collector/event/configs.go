package event

import (
	"collector/eventmanager"

	"github.com/chriskaliX/SDK"

	"collector/event/configs"
)

type Configs struct{}

func (Configs) DataType() int { return 9998 }

func (Configs) Name() string { return "configs" }

func (Configs) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (Configs) Immediately() bool { return false }

func (l *Configs) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	for event := range configs.Events {
		event.Run(s, sig)
	}
	return
}
