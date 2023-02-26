package web

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type Apache2 struct {
	version string
	reg     *regexp.Regexp
}

func (Apache2) Name() string { return "apache2" }

func (Apache2) Type() string { return "web" }

func (a Apache2) Version() string { return a.version }

func (Apache2) Match(p *process.Process) bool { return p.Name == "apache2" }

func (a *Apache2) Run(p *process.Process) (m map[string]string, err error) {
	if a.reg == nil {
		a.reg = regexp.MustCompile(`Apache2\/(\d+\.)+\d+`)
	}
	result, err := apps.Execute(p, "-v")
	str := a.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	a.version = strings.TrimPrefix(str, "Apache2/")
	return
}

func init() {
	apps.Regist(&Apache2{})
}
