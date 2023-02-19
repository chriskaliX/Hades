package web

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type Nginx struct {
	version string
	rp      *regexp.Regexp
}

func (Nginx) Name() string { return "nginx" }

func (Nginx) Type() string { return "web" }

func (n Nginx) Version() string { return n.version }

func (Nginx) Match(p *process.Process) bool {
	// As default, nginx runs with master_process
	// ignore the other processes, and report the worker process if we need
	return p.Name == "nginx" && strings.Contains(p.Argv, "master")
}

func (n *Nginx) Run(p *process.Process) (m map[string]string, err error) {
	result, err := apps.Execute(p, "-v")
	if n.rp == nil {
		n.rp = regexp.MustCompile(`nginx\/(\d+\.)+\d+`)
	}
	str := n.rp.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	n.version = strings.TrimPrefix(str, "nginx/")
	m = make(map[string]string)
	if strings.Contains(p.Argv, "master process") {
		m["process_type"] = "master"
	} else {
		m["process_type"] = "worker"
	}
	return
}

func init() {
	apps.Regist(&Nginx{})
}
