package web

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
)

type Apache2 struct {
	version string
	rp      *regexp.Regexp
}

func (Apache2) Name() string { return "apache2" }

func (Apache2) Type() string { return "web" }

func (a Apache2) Version() string { return a.version }

func (Apache2) Match(p *process.Process) bool { return p.Name == "apache2" }

func (a *Apache2) Run(p *process.Process) (m map[string]string, err error) {
	return
}

func init() {
	apps.Regist(&Apache2{})
}
