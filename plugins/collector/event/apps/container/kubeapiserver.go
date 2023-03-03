package container

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type KubeApiserver struct {
	version string
	reg     *regexp.Regexp
}

func (KubeApiserver) Name() string { return "kube-apiserver" }

func (KubeApiserver) Type() string { return "container" }

func (d KubeApiserver) Version() string { return d.version }

func (KubeApiserver) Match(p *process.Process) bool { return p.Name == "kube-apiserver" }

func (n *KubeApiserver) Run(p *process.Process) (m map[string]string, err error) {
	if n.reg == nil {
		n.reg = regexp.MustCompile(`Kubernetes v(\d+\.)+\d+`)
	}
	result, err := apps.Execute(p, "--version")
	str := n.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	n.version = strings.TrimPrefix(str, "Kubernetes v")
	return
}

func init() { apps.Regist(&KubeApiserver{}) }
