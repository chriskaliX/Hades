package container

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type Kubelet struct {
	version string
	reg     *regexp.Regexp
}

func (Kubelet) Name() string { return "kubelet" }

func (Kubelet) Type() string { return "container" }

func (d Kubelet) Version() string { return d.version }

func (Kubelet) Match(p *process.Process) bool { return p.Name == "kubelet" }

func (n *Kubelet) Run(p *process.Process) (m map[string]string, err error) {
	if n.reg == nil {
		n.reg = regexp.MustCompile(`v(\d+\.)+\d+\S+`)
	}
	result, err := apps.Execute(p, "--version")
	str := n.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	n.version = strings.TrimPrefix(str, "v")
	return
}

func init() { apps.Regist(&Kubelet{}) }
