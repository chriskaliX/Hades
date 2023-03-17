package web

import (
	"collector/cache/process"
	"collector/event/apps"
	"strings"
)

type Openresty struct {
	version string
}

func (Openresty) Name() string { return "openresty" }

func (Openresty) Type() string { return "web" }

func (n Openresty) Version() string { return n.version }

func (Openresty) Match(p *process.Process) bool {
	// As default, nginx runs with master_process
	// ignore the other processes, and report the worker process if we need
	return p.Name == "openresty"
}

// Tengine matches too
func (n *Openresty) Run(p *process.Process) (m map[string]string, err error) {
	result, err := apps.Execute(p, "-v")
	if err != nil {
		return
	}
	n.version = strings.TrimPrefix(result, "openresty/")
	return
}

func init() { apps.Regist(&Openresty{}) }
