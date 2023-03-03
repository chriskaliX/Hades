package database

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type Etcd struct {
	version string
	reg     *regexp.Regexp
}

func (Etcd) Name() string { return "etcd" }

func (Etcd) Type() string { return "database" }

func (e Etcd) Version() string { return e.version }

func (Etcd) Match(p *process.Process) bool { return p.Name == "etcd" }

func (e *Etcd) Run(p *process.Process) (mapping map[string]string, err error) {
	if e.reg == nil {
		e.reg = regexp.MustCompile(`etcd Version: (\d+\.)+\d+`)
	}
	result, err := apps.Execute(p, "--version")
	if err != nil {
		return nil, err
	}
	str := e.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	e.version = strings.TrimPrefix(str, "etcd Version: ")
	return
}

func init() { apps.Regist(&Etcd{}) }
