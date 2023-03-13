// Applications collection which is cloud compatible, container specificated
package apps

import (
	"collector/cache/process"
	"collector/cache/socket"
	"collector/container"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var Apps = make([]IApplication, 0)

var (
	ErrVersionNotFound = errors.New("version not found")
	ErrIgnore          = errors.New("ignore")
)

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
		Apps = append(Apps, app)
	default:
		Apps = append([]IApplication{app}, Apps...)
	}
}

func Execute(p *process.Process, args ...string) (result string, err error) {
	return ExecuteWithName(p, p.Exe, args...)
}

func ExecuteWithName(p *process.Process, name string, args ...string) (result string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	// TODO: Safely get the version information from Exec? privileged escalation and evasion may encounter
	if p.IsContainer() {
		// In container, we need to execute inside the container, all containers implementation (docker & cri)
		// should support the Exec arguments

		// cmd := exec.CommandContext(ctx, filepath.Join("/proc", strconv.Itoa(p.PID), "root", name), args...)
		// cmd.SysProcAttr = &syscall.SysProcAttr{
		// 	Setpgid:                    true,
		// 	GidMappingsEnableSetgroups: true,
		// 	Credential:                 &syscall.Credential{Uid: uint32(p.UID), Gid: uint32(p.GID)},
		// 	Cloneflags:                 syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		// 	UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		// 	GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		// }
		// cmd.Env = os.Environ()
		// cmd.Dir = filepath.Join("/proc", strconv.Itoa(p.PID), "root", p.Cwd)
		// var vbytes []byte
		// vbytes, err = cmd.CombinedOutput()
		// if err != nil {
		// 	return result, err
		// }
		// result = string(vbytes)

		// Using clients to execute inside the container
		return container.DefaultClient.Exec(uint32(p.Pns), name, args...)
	} else {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(p.UID),
				Gid: uint32(p.GID),
			},
		}
		cmd.Dir = p.Cwd
		var vbytes []byte
		vbytes, err = cmd.CombinedOutput()
		if err != nil {
			return result, err
		}
		result = string(vbytes)
	}
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
			if soc, ok := socket.Get(uint32(inode)); ok && soc.State == "10" {
				addrs = append(addrs, soc.SIP+":"+soc.SPort)
			}
		}
	}
	return strings.Join(addrs, ",")
}
