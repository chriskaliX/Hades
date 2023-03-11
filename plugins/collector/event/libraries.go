package event

import (
	"collector/eventmanager"

	"github.com/chriskaliX/SDK"

	ls "collector/event/libraries"
)

type Libraries struct{}

func (Libraries) DataType() int { return 9999 }

func (Libraries) Name() string { return "libraries" }

func (Libraries) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (Libraries) Immediately() bool { return false }

func (l *Libraries) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	for event := range ls.Events {
		event.Run(s, sig)
	}
	return
}
