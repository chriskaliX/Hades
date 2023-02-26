package bigdata

import (
	"collector/cache/process"
	"collector/event/apps"
	"path/filepath"
	"regexp"
	"strings"
)

type Hadoop struct {
	version    string
	reg        *regexp.Regexp
	regDir     *regexp.Regexp
	regVersion *regexp.Regexp
	mainclass  string
}

func (Hadoop) Name() string { return "hadoop" }

func (Hadoop) Type() string { return "bigdata" }

func (h Hadoop) Version() string { return h.version }

func (h *Hadoop) Match(p *process.Process) bool {
	if p.Name != "java" {
		return false
	}
	if h.reg == nil {
		h.reg = regexp.MustCompile(` org\.apache\.hadoop\.[a-zA-Z\.]+\.DataNode`)
	}
	if s := h.reg.FindString(p.Argv); s == "" {
		return false
	} else {
		h.mainclass = s
	}
	return true
}

func (h *Hadoop) Run(p *process.Process) (m map[string]string, err error) {
	m = make(map[string]string)
	if h.regDir == nil {
		h.regDir = regexp.MustCompile(`hadoop.home.dir=[a-zA-Z0-9\/-_]+`)
	}
	if h.regVersion == nil {
		h.regVersion = regexp.MustCompile(`Hadoop (\d+\.)+\d`)
	}

	var rootPath = "/usr/local/hadoop"
	if s := h.regDir.FindString(p.Argv); s != "" {
		rootPath = strings.TrimPrefix(s, "hadoop.home.dir=")
	}
	if result, err := apps.ExecuteWithName(p, filepath.Join(rootPath, "bin/hadoop"), "version"); err == nil {
		if s := h.regVersion.FindString(result); s != "" {
			h.version = strings.TrimPrefix(s, "Hadoop ")
		}
	}
	m["main_class"] = h.mainclass
	return
}

func init() { apps.Regist(&Hadoop{}) }
