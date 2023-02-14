package midware

import (
	"collector/cache/process"
	"collector/event/apps"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
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
	if p.Name == "nginx" && strings.Contains(p.Argv, "master process") {
		return true
	}
	return false
}

func (n *Nginx) Run(p *process.Process) (result string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	// TODO: Safely get the version information from Exec? privileged escalation and evasion may encounter.
	// IS PARSING ELF POSSIBLE?
	// TODO: EXEUTE WITHIN CONTAINER? CAN WE READ FROM ELF?
	cmd := exec.CommandContext(ctx, p.Exe, "-v")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(p.UID),
			Gid: uint32(p.GID),
		},
	}
	cmd.Dir = p.Cwd
	vbytes, err := cmd.CombinedOutput()
	if err != nil {
		return result, err
	}
	if n.rp == nil {
		n.rp = regexp.MustCompile(`nginx\/(\d+\.)+\d+`)
	}
	resbytes := n.rp.Find(vbytes)
	if resbytes == nil {
		err = fmt.Errorf("version not found, %s", string(vbytes))
		return
	}
	n.version = strings.TrimPrefix(string(resbytes), "nginx/")
	return
}

func init() {
	apps.Regist(&Nginx{})
}
