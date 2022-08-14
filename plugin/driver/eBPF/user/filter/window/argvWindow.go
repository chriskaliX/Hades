package window

import "time"

// argv filter not added for now
const (
	argvDynQuota = 1500
	argvDuration = 60 * time.Second
	argvSize     = 512
)

var DefaultArgvWindow = NewArgvWindow()

func NewArgvWindow() *Window {
	return NewWindow(argvDynQuota, argvDuration, argvSize)
}
