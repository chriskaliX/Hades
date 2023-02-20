package database

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type PostgreSql struct {
	version string
	reg     *regexp.Regexp
}

func (PostgreSql) Name() string { return "postgresql" }

func (PostgreSql) Type() string { return "database" }

func (p PostgreSql) Version() string { return p.version }

func (PostgreSql) Match(proc *process.Process) bool {
	return proc.Name == "postgres" && strings.Contains(proc.Argv, "config_file")
}

func (p *PostgreSql) Run(proc *process.Process) (mapping map[string]string, err error) {
	if p.reg == nil {
		p.reg = regexp.MustCompile(`(\d+\.)+\d+`)
	}
	result, err := apps.Execute(proc, "-V")
	if err != nil {
		return nil, err
	}
	str := p.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	p.version = str
	return
}

func init() {
	apps.Regist(&PostgreSql{})
}
