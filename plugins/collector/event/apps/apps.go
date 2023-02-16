// Applications collection which is cloud compatible, container specificated
package apps

import (
	"collector/cache/process"
	"collector/cache/socket"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var Apps = make([]IApplication, 0)

// Just for temporary
type IApplication interface {
	Name() string
	Type() string
	Version() string

	Run(*process.Process) (m map[string]string, err error)
	Match(*process.Process) bool // Whether the process matches
}

// regist the application into slice
func Regist(app IApplication) {
	switch app.Type() {
	case "software":
		Apps = append([]IApplication{app}, Apps...)
	default:
		Apps = append(Apps, app)
	}
}

// TODO: container
func Execute(p *process.Process, args ...string) (result string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	// TODO: Safely get the version information from Exec? privileged escalation and evasion may encounter.
	// IS PARSING ELF POSSIBLE?
	// TODO: EXEUTE WITHIN CONTAINER? CAN WE READ FROM ELF?
	cmd := exec.CommandContext(ctx, p.Exe, args...)
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
	result = string(vbytes)
	return
}

func ProcListenAddrs(proc *process.Process) string {
	var addrs []string
	// add listening port if it's an web application
	if fds, err := proc.Fds(); err == nil {
		for _, fd := range fds {
			if !strings.HasPrefix(fd, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimRight(fd[8:], "]"), 10, 32)
			if err != nil {
				continue
			}
			if soc, ok := socket.Get(uint32(inode)); ok && soc.State == 10 {
				addrs = append(addrs, soc.SIP.String()+":"+strconv.Itoa(int(soc.SPort)))
			}
		}
	}
	return strings.Join(addrs, ",")
}
