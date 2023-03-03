package container

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type Docker struct {
	version string
	reg     *regexp.Regexp
}

func (Docker) Name() string { return "docker" }

func (Docker) Type() string { return "container" }

func (d Docker) Version() string { return d.version }

func (Docker) Match(p *process.Process) bool { return p.Name == "dockerd" }

func (n *Docker) Run(p *process.Process) (m map[string]string, err error) {
	if n.reg == nil {
		n.reg = regexp.MustCompile(`Docker\sversion\s(\d+\.)+\d+`)
	}
	result, err := apps.Execute(p, "--version")
	str := n.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	n.version = strings.TrimPrefix(str, "Docker version ")
	return
}

func init() { apps.Regist(&Docker{}) }
