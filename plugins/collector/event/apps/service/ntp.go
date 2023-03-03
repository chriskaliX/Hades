package service

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type Ntp struct {
	version string
	reg     *regexp.Regexp
}

func (Ntp) Name() string { return "ntp" }

func (Ntp) Type() string { return "service" }

func (n Ntp) Version() string { return n.version }

func (Ntp) Match(p *process.Process) bool { return p.Name == "ntpd" }

func (n *Ntp) Run(p *process.Process) (m map[string]string, err error) {
	if n.reg == nil {
		n.reg = regexp.MustCompile(`ntpd (\d+\.)+\d+`)
	}
	result, err := apps.Execute(p, "--version")
	str := n.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	n.version = strings.TrimPrefix(str, "ntpd ")
	return
}

func init() { apps.Regist(&Ntp{}) }
