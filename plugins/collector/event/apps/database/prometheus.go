package database

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type Prometheus struct {
	version string
	reg     *regexp.Regexp
}

func (Prometheus) Name() string { return "prometheus" }

func (Prometheus) Type() string { return "database" }

func (p Prometheus) Version() string { return p.version }

func (Prometheus) Match(p *process.Process) bool { return p.Name == "prometheus" }

// Elkeid, failed to install in my ubuntu :-(
func (p *Prometheus) Run(proc *process.Process) (mapping map[string]string, err error) {
	if p.reg == nil {
		p.reg = regexp.MustCompile(`prometheus,\sversion\s(\d+\.)+\d+`)
	}
	result, err := apps.Execute(proc, "--version")
	if err != nil {
		return nil, err
	}
	str := p.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	p.version = strings.TrimPrefix(str, "prometheus, version ")
	return
}

func init() {
	apps.Regist(&Prometheus{})
}
