package bigdata

import (
	"collector/cache/process"
	"collector/event/apps"
	"path/filepath"
	"regexp"
	"strings"
)

// Hadoop database, put this in bigdata temporary
type Hbase struct {
	version    string
	reg        *regexp.Regexp
	regDir     *regexp.Regexp
	regVersion *regexp.Regexp
}

func (Hbase) Name() string { return "hbase" }

func (Hbase) Type() string { return "bigdata" }

func (h Hbase) Version() string { return h.version }

func (h *Hbase) Match(p *process.Process) bool {
	if p.Name != "java" {
		return false
	}
	if h.reg == nil {
		h.reg = regexp.MustCompile(` org\.apache\.hadoop\.hbase\.master`)
	}
	if s := h.reg.FindString(p.Argv); s == "" {
		return false
	}
	return true
}

func (h *Hbase) Run(p *process.Process) (m map[string]string, err error) {
	m = make(map[string]string)
	if h.regDir == nil {
		h.regDir = regexp.MustCompile(`hbase.home.dir=[a-zA-Z0-9\/-_]+`)
	}
	if h.regVersion == nil {
		h.regVersion = regexp.MustCompile(`HBase (\d+\.)+\d`)
	}
	var rootPath string
	if s := h.regDir.FindString(p.Argv); s != "" {
		rootPath = strings.TrimPrefix(s, "hbase.home.dir=")
	} else {
		return
	}
	if result, err := apps.ExecuteWithName(p, filepath.Join(rootPath, "hbase"), "version"); err == nil {
		if s := h.regVersion.FindString(result); s != "" {
			h.version = strings.TrimPrefix(s, "HBase ")
		}
	}
	return
}

func init() { apps.Regist(&Hbase{}) }
