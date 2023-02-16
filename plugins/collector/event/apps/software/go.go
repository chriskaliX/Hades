package software

import (
	"collector/cache/process"
	"collector/event/apps"
	"debug/buildinfo"
	"strings"
)

// TODO: golang application should get the lowest priority
// since other applications like docker / etcd.
type Golang struct {
	version string
	info    *buildinfo.BuildInfo
}

func (Golang) Name() string { return "golang" }

func (Golang) Type() string { return "software" }

func (g Golang) Version() string { return g.version }

func (g *Golang) Match(p *process.Process) bool {
	// Need to parse the elf
	bi, err := buildinfo.ReadFile(p.Exe)
	if err != nil {
		return false
	}
	g.version = strings.TrimPrefix(bi.GoVersion, "go")
	g.info = bi
	return true
}

func (g *Golang) Run(p *process.Process) (m map[string]string, err error) {
	if g.info == nil {
		return
	}
	return
}

func init() {
	apps.Regist(&Golang{})
}
