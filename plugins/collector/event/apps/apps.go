// Applications collection which is cloud compatible, container specificated
package apps

import (
	"collector/cache/process"
)

var Apps = make(map[string]IApplication)

// Just for temporary
type IApplication interface {
	Name() string
	Type() string
	Version() string

	Run(*process.Process) (str string, err error)
	Match(*process.Process) bool // Whether the process matches
}

func Regist(app IApplication) {
	Apps[app.Name()] = app
}
