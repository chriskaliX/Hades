package bigdata

import (
	"collector/cache/process"
	"collector/event/apps"
	"path/filepath"
	"strings"
)

const rabbitmqctl = "/usr/sbin/rabbitmqctl"

type Rabbitmq struct {
	version string
}

func (Rabbitmq) Name() string { return "rabbitmq" }

func (Rabbitmq) Type() string { return "bigdata" }

func (r Rabbitmq) Version() string { return r.version }

// run within container or as a service
func (r *Rabbitmq) Match(p *process.Process) bool {
	return p.Name == "beam.smp"
}

func (r *Rabbitmq) Run(p *process.Process) (m map[string]string, err error) {
	// Two situation here:
	// 1. install from yum/apt, deamon process is systemd (ppid 1)
	// 2. pull from the docker, deamon process is rabbitmq-server
	// But it is not an absolutely thing. We need to double check for this
	r.version = ""
	if strings.Contains(p.PpidArgv, "rabbitmq-server") {
		var proc *process.Process
		var fds []string
		proc, err = process.GetProcessInfo(p.PPID, false)
		if err != nil {
			return
		}
		if fds, err = proc.Fds(); err != nil {
			return
		}
		for _, fd := range fds {
			if filepath.Base(fd) != "rabbitmq-server" {
				continue
			}
			// get the sbin
			result, err := apps.ExecuteWithName(p, filepath.Join(filepath.Dir(fd), "rabbitmqctl"), "version")
			if err == nil {
				r.version = strings.TrimSpace(result)
			}
			break
		}
	} else {
		// systemd, try to get the path of rabbitmq
		result, err := apps.ExecuteWithName(p, "rabbitmqctl", "version")
		if err == nil {
			r.version = strings.TrimSpace(result)
		}
	}
	return
}

func init() { apps.Regist(&Rabbitmq{}) }
