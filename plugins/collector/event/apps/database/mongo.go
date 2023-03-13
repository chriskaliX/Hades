package database

import (
	"collector/cache/process"
	"collector/event/apps"
	"strings"
)

type MongoDB struct {
	version string
}

func (MongoDB) Name() string { return "mongo" }

func (MongoDB) Type() string { return "database" }

func (m MongoDB) Version() string { return m.version }

func (m *MongoDB) Match(p *process.Process) bool { return p.Name == "mongod" }

func (m *MongoDB) Run(p *process.Process) (mapping map[string]string, err error) {
	result, err := apps.Execute(p, "--version")
	if err != nil {
		return nil, err
	}
	m.version = strings.TrimPrefix(strings.Split(result, "\n")[0], "db version v")
	return
}

func init() { apps.Regist(&MongoDB{}) }
