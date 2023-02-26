package bigdata

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

// Totally work on argv, unreliable maybe, but useful
type Flink struct {
	version    string
	reg        *regexp.Regexp
	versionReg *regexp.Regexp
}

func (Flink) Name() string { return "flink" }

func (Flink) Type() string { return "bigdata" }

func (f Flink) Version() string { return f.version }

func (f *Flink) Match(p *process.Process) bool {
	if p.Name != "java" {
		return false
	}
	if f.reg == nil {
		f.reg = regexp.MustCompile(` org\.apache\.flink\.[a-zA-Z\.]+`)
	}
	if s := f.reg.FindString(p.Argv); s == "" {
		return false
	}
	return true
}

func (f *Flink) Run(p *process.Process) (m map[string]string, err error) {
	// temporary files like /tmp/hsperfdata_(username)
	if f.versionReg == nil {
		f.versionReg = regexp.MustCompile(`flink-dist-(\d+\.)+\d\.jar`)
	}
	if s := f.versionReg.FindString(p.Argv); s != "" {
		f.version = strings.TrimRight(strings.TrimPrefix(s, "flink-dist-"), ".jar")
	}
	// jobmanager or taskmanager
	m = make(map[string]string)
	if strings.Contains(p.Argv, "jobmanager.") {
		m["run_mode"] = "jobmanager"
	} else if strings.Contains(p.Argv, "taskmanager.") {
		m["run_mode"] = "taskmanager"
	} else {
		m["run_mode"] = "unknown"
	}

	return
}

func init() { apps.Regist(&Flink{}) }
