package database

import (
	"collector/cache/process"
	"collector/event/apps"
	"strings"
)

type Memcache struct {
	version string
}

func (Memcache) Name() string { return "memcache" }

func (Memcache) Type() string { return "database" }

func (m Memcache) Version() string { return m.version }

func (m *Memcache) Match(p *process.Process) bool { return p.Name == "memcached" }

func (m *Memcache) Run(p *process.Process) (mapping map[string]string, err error) {
	result, err := apps.Execute(p, "--version")
	if err != nil {
		return nil, err
	}
	m.version = strings.Trim(strings.TrimPrefix(result, "memcached "), "\n")
	return
}

func init() {
	apps.Regist(&Memcache{})
}
