package software

import (
	"collector/cache/process"
	"collector/event/apps"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/version"
)

// TODO: recognition of weblogic/jboss
type Java struct {
	version  string
	jarCache map[string]int64
	once     sync.Once
}

func (Java) Name() string { return "java" }

func (Java) Type() string { return "software" }

func (j Java) Version() string { return j.version }

func (Java) Match(p *process.Process) bool { return p.Name == "java" }

func (j *Java) Run(p *process.Process) (m map[string]string, err error) {
	j.once.Do(func() { j.jarCache = make(map[string]int64) })
	m = make(map[string]string)
	if err = j.getVersion(p, m); err != nil {
		return
	}
	// get from fds (how jps works?), 1024 limitation
	// if fds, err := p.Fds(); err == nil {
	// 	m["fd_count"] = strconv.Itoa(len(fds))
	// 	for _, fd := range fds {
	// 		// skip if not jar
	// 		if filepath.Ext(fd) != ".jar" {
	// 			continue
	// 		}
	// 		// skip packet in bootstrap classloader
	// 		if filepath.Base(fd) == "rt.jar" {
	// 			continue
	// 		}
	// 		// skip if already in the cache
	// 		info, err := os.Stat(fd)
	// 		if err != nil {
	// 			continue
	// 		}
	// 		if size, ok := j.jarCache[fd]; ok && size == info.Size() {
	// 			continue
	// 		}
	// 	}
	// }
	return
}

func (j *Java) getVersion(p *process.Process, m map[string]string) error {
	// version
	j.version = ""
	jversion, err := apps.Execute(p, "-version")
	if err != nil {
		return err
	}
	for index, v := range strings.Split(jversion, "\n") {
		if index == 0 {
			m["version_detail"] = v
		}
		for _, field := range strings.Split(v, " ") {
			if vs, err := version.ParseGeneric(field); err == nil {
				j.version = vs.String()
				break
			}
		}
		if j.version != "" {
			break
		}
	}
	return nil
}

func init() {
	apps.Regist(&Java{})
}
