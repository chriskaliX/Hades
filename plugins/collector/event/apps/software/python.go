package software

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type Python struct {
	version string
	r       *regexp.Regexp
}

func (Python) Name() string { return "python" }

func (Python) Type() string { return "software" }

func (p Python) Version() string { return p.version }

func (p *Python) Match(proc *process.Process) bool {
	if p.r == nil {
		p.r = regexp.MustCompile("^python\\d(\\.\\d+)$")
	}
	str := p.r.FindString(proc.Name)
	if str == "" {
		return false
	}
	p.version = strings.TrimPrefix(str, "python")
	return true
}

func (p *Python) Run(proc *process.Process) (m map[string]string, err error) {
	return
}

func init() {
	apps.Regist(&Python{})
}
