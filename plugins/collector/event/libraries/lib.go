package libraries

import "github.com/chriskaliX/SDK"

var Events = make(map[Lib]struct{})

type Lib interface {
	Run(s SDK.ISandbox, sig chan struct{}) (err error)
}

func addEvent(lib Lib) {
	Events[lib] = struct{}{}
}
