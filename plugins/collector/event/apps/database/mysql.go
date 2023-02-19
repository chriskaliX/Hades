package database

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type Mysql struct {
	version string
	r       *regexp.Regexp
}

func (Mysql) Name() string { return "mysql" }

func (Mysql) Type() string { return "database" }

func (m Mysql) Version() string { return m.version }

func (Mysql) Match(p *process.Process) bool { return p.Name == "mysqld" }

func (m *Mysql) Run(p *process.Process) (mapping map[string]string, err error) {
	if m.r == nil {
		m.r = regexp.MustCompile(`Ver\s(\d+\.)+\d+`)
	}
	result, err := apps.Execute(p, "-V")
	if err != nil {
		return nil, err
	}
	str := m.r.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	m.version = strings.TrimPrefix(str, "Ver ")
	return
}

func init() {
	apps.Regist(&Mysql{})
}
