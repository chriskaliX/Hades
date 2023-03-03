package service

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type Nscd struct {
	version string
	reg     *regexp.Regexp
}

func (Nscd) Name() string { return "nscd" }

func (Nscd) Type() string { return "service" }

func (n Nscd) Version() string { return n.version }

func (Nscd) Match(p *process.Process) bool { return p.Name == "nscd" }

func (n *Nscd) Run(p *process.Process) (m map[string]string, err error) {
	if n.reg == nil {
		n.reg = regexp.MustCompile(`nscd \(.*?\) (\d+\.)+\d+`)
	}
	result, err := apps.Execute(p, "--version")
	str := n.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	slice := strings.Split(result, " ")
	n.version = slice[len(slice)-1]
	return
}

func init() { apps.Regist(&Nscd{}) }
