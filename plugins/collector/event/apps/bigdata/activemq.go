package bigdata

import (
	"collector/cache/process"
	"collector/event/apps"
	"path/filepath"
	"regexp"
	"strings"
)

type Activemq struct {
	version    string
	regVersion *regexp.Regexp
}

func (Activemq) Name() string { return "activemq" }

func (Activemq) Type() string { return "bigdata" }

func (m Activemq) Version() string { return m.version }

func (m *Activemq) Match(p *process.Process) bool {
	if p.Name != "java" {
		return false
	}
	if m.regVersion == nil {
		m.regVersion = regexp.MustCompile(`activemq-client-(\d+\.)+(\d+)\.jar`)
	}
	m.version = ""
	fds, err := p.Fds()
	if err != nil {
		return false
	}
	for _, fd := range fds {
		if filepath.Ext(fd) != ".jar" {
			continue
		}
		if res := m.regVersion.FindString(filepath.Base(fd)); res != "" {
			m.version = strings.TrimRight(strings.TrimPrefix(res, "activemq-client-"), ".jar")
			break
		}
	}
	if m.version == "" {
		return false
	}
	return true
}

func (m *Activemq) Run(p *process.Process) (result map[string]string, err error) {
	return
}

func init() { apps.Regist(&Activemq{}) }
