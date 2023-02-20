package database

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
)

type Sqlserver struct {
	version string
	reg     *regexp.Regexp
}

func (Sqlserver) Name() string { return "sqlserver" }

func (Sqlserver) Type() string { return "database" }

func (e Sqlserver) Version() string { return e.version }

func (Sqlserver) Match(p *process.Process) bool { return p.Name == "sqlserver" }

func (e *Sqlserver) Run(p *process.Process) (mapping map[string]string, err error) {
	if e.reg == nil {
		e.reg = regexp.MustCompile(`(\d+\.){3}\d+`)
	}
	result, err := apps.Execute(p, "-v")
	if err != nil {
		return nil, err
	}
	str := e.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	return
}

func init() {
	apps.Regist(&Sqlserver{})
}
