package bigdata

import (
	"collector/cache/process"
	"collector/event/apps"
	"path/filepath"
	"regexp"
	"strings"
)

type Zookeeper struct {
	version    string
	reg        *regexp.Regexp
	regVersion *regexp.Regexp
}

func (Zookeeper) Name() string { return "zookeeper" }

func (Zookeeper) Type() string { return "bigdata" }

func (z Zookeeper) Version() string { return z.version }

func (z *Zookeeper) Match(p *process.Process) bool {
	if p.Name != "java" {
		return false
	}
	if z.reg == nil {
		z.reg = regexp.MustCompile(` org\.apache\.zookeeper\.`)
	}
	if res := z.reg.FindString(p.Argv); res == "" {
		return false
	}
	return true
}

func (z *Zookeeper) Run(p *process.Process) (m map[string]string, err error) {
	if z.regVersion == nil {
		z.regVersion = regexp.MustCompile(`zookeeper-(\d+\.)+(\d+)\.jar`)
	}
	// get the version
	var fds []string
	if fds, err = p.Fds(); err != nil {
		return
	}
	for _, fd := range fds {
		if filepath.Ext(fd) != ".jar" {
			continue
		}
		if res := z.regVersion.FindString(filepath.Base(fd)); res != "" {
			z.version = strings.TrimRight(strings.TrimPrefix(res, "zookeeper-"), ".jar")
			break
		}
	}
	return
}

func init() { apps.Regist(&Zookeeper{}) }
