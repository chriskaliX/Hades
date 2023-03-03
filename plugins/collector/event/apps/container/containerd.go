package container

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
)

type Containerd struct {
	version string
	reg     *regexp.Regexp
}

func (Containerd) Name() string { return "containerd" }

func (Containerd) Type() string { return "container" }

func (d Containerd) Version() string { return d.version }

func (Containerd) Match(p *process.Process) bool { return p.Name == "containerd" }

func (n *Containerd) Run(p *process.Process) (m map[string]string, err error) {
	if n.reg == nil {
		n.reg = regexp.MustCompile(`(\d+\.)+\d+`)
	}
	result, err := apps.Execute(p, "--version")
	str := n.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	n.version = str
	return
}

func init() { apps.Regist(&Containerd{}) }
