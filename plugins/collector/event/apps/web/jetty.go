package web

import (
	"collector/cache/process"
	"collector/event/apps"
	"path/filepath"
	"regexp"
	"strings"
)

type Jetty struct {
	version string
	reg     *regexp.Regexp
}

func (Jetty) Name() string { return "jetty" }

func (Jetty) Type() string { return "web" }

func (j Jetty) Version() string { return j.version }

func (j *Jetty) Match(p *process.Process) bool {
	if p.Name != "java" {
		return false
	}
	fds, err := p.Fds()
	if err != nil {
		return false
	}
	if j.reg == nil {
		j.reg = regexp.MustCompile(`jetty-client-(\d+\.)+(\d+)\.jar`)
	}
	for _, fd := range fds {
		if filepath.Ext(fd) != ".jar" {
			continue
		}
		if s := j.reg.FindString(filepath.Base(fd)); s != "" {
			j.version = strings.TrimSuffix(strings.TrimPrefix(s, "jetty-client-"), ".jar")
			return true
		}
	}
	return false
}

func (n *Jetty) Run(p *process.Process) (m map[string]string, err error) {
	return
}

func init() { apps.Regist(&Jetty{}) }
