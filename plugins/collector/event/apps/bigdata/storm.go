package bigdata

import (
	"collector/cache/process"
	"collector/event/apps"
	"path/filepath"
	"regexp"
	"strings"
)

type Storm struct {
	version    string
	reg        *regexp.Regexp
	regVersion *regexp.Regexp
}

func (Storm) Name() string { return "storm" }

func (Storm) Type() string { return "bigdata" }

func (s Storm) Version() string { return s.version }

func (s *Storm) Match(p *process.Process) bool {
	if p.Name != "java" {
		return false
	}
	if s.reg == nil {
		s.reg = regexp.MustCompile(` org\.apache\.storm\.daemon\.`)
	}
	if res := s.reg.FindString(p.Argv); res == "" {
		return false
	}
	return true
}

func (s *Storm) Run(p *process.Process) (m map[string]string, err error) {
	s.version = ""
	if s.regVersion == nil {
		s.regVersion = regexp.MustCompile(`storm-client-(\d+\.)+(\d+)\.jar`)
	}

	m = make(map[string]string)
	// check run mode
	// or report the mainclass as well
	if strings.Contains(p.Argv, " org.apache.storm.daemon.nimbus.Nimbus") {
		m["run_mode"] = "nimbus"
	} else if strings.Contains(p.Argv, " org.apache.storm.daemon.ui.UIServer") {
		m["run_mode"] = "uiserver"
	} else if strings.Contains(p.Argv, " org.apache.storm.daemon.supervisor.Supervisor") {
		m["run_mode"] = "supervisor"
	} else {
		m["run_mode"] = "unknown"
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
		if res := s.regVersion.FindString(filepath.Base(fd)); res != "" {
			s.version = strings.TrimRight(strings.TrimPrefix(res, "storm-client-"), ".jar")
			break
		}
	}
	return
}

func init() { apps.Regist(&Storm{}) }
