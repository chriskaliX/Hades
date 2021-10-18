package collector

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"agent/global"
	"agent/global/structs"
	"agent/network"

	"math/rand"
	"os"
	"os/user"
	"strconv"
	"strings"

	"agent/utils"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

const MaxProcess = 5000

// 获取进程
// 直接搬运，写的很好
func GetProcess() (procs []structs.Process, err error) {
	var allProc procfs.Procs
	var sys procfs.Stat
	allProc, err = procfs.AllProcs()
	if err != nil {
		return
	}
	sys, err = procfs.NewStat()
	if err != nil {
		return
	}

	// 如果超出最大进程数, 则shuffle打乱后获取 MaxProcess 大小
	if len(allProc) > MaxProcess {
		rand.Shuffle(len(allProc), func(i, j int) {
			allProc[i], allProc[j] = allProc[j], allProc[i]
		})
		allProc = allProc[:MaxProcess]
	}
	for _, p := range allProc {
		var err error
		proc := structs.Process{PID: p.PID}
		proc.Exe, err = p.Executable()
		if err != nil {
			continue
		}
		_, err = os.Stat(proc.Exe)
		if err != nil {
			continue
		}
		status, err := p.NewStatus()
		if err == nil {
			proc.UID = status.UIDs[0]
			proc.EUID = status.UIDs[1]
			proc.Name = status.Name
		} else {
			continue
		}
		state, err := p.Stat()
		if err == nil {
			proc.PPID = state.PPID
			proc.Session = state.Session
			proc.TTY = state.TTY
			proc.StartTime = sys.BootTime + state.Starttime/100
		} else {
			continue
		}
		proc.Cwd, err = p.Cwd()
		if err != nil {
			continue
		}
		cmdline, err := p.CmdLine()
		if err != nil {
			continue
		} else {
			if len(cmdline) > 32 {
				cmdline = cmdline[:32]
			}
			proc.Cmdline = strings.Join(cmdline, " ")
			if len(proc.Cmdline) > 64 {
				proc.Cmdline = proc.Cmdline[:64]
			}
		}
		proc.Sha256, _ = utils.GetSha256ByPath("/proc/" + strconv.Itoa(proc.PID) + "/exe")
		u, err := user.LookupId(proc.UID)
		if err == nil {
			proc.Username = u.Username
		}
		eu, err := user.LookupId(proc.EUID)
		if err == nil {
			proc.Eusername = eu.Username
		}
		procs = append(procs, proc)
	}
	return
}

var ProcessPool = sync.Pool{
	New: func() interface{} {
		return new(structs.Process)
	},
}

// 获取单个 process 信息
// 改造一下, 用于补足单个进程的完整信息
func GetProcessInfo(pid uint32) (structs.Process, error) {
	var (
		err  error
		proc structs.Process
	)

	process, err := procfs.NewProc(int(pid))
	if err != nil {
		return proc, errors.New("no process found")
	}

	proc = structs.ProcessPool.Get().(structs.Process)
	proc.PID = process.PID

	status, err := process.NewStatus()
	if err == nil {
		proc.UID = status.UIDs[0]
		proc.EUID = status.UIDs[1]
		proc.Name = status.Name
	}

	state, err := process.Stat()
	if err == nil {
		proc.PPID = state.PPID
		proc.Session = state.Session
		proc.TTY = state.TTY
		proc.StartTime = uint64(global.Time)
	}

	proc.Cwd, err = process.Cwd()
	cmdline, err := process.CmdLine()
	if err != nil {
	} else {
		if len(cmdline) > 32 {
			cmdline = cmdline[:32]
		}
		proc.Cmdline = strings.Join(cmdline, " ")
		if len(proc.Cmdline) > 64 {
			proc.Cmdline = proc.Cmdline[:64]
		}
	}

	proc.Exe, err = process.Executable()
	if err == nil {
		_, err = os.Stat(proc.Exe)
		if err == nil {
			proc.Sha256, _ = utils.GetSha256ByPath(proc.Exe)
		}
	}

	// 修改本地缓存加速
	username, ok := global.UsernameCache.Load(proc.UID)
	if ok {
		proc.Username = username.(string)
	} else {
		u, err := user.LookupId(proc.UID)
		if err == nil {
			proc.Username = u.Username
			global.UsernameCache.Store(proc.UID, u.Username)
		}
	}

	// 修改本地缓存加速
	eusername, ok := global.UsernameCache.Load(proc.EUID)

	if ok {
		proc.Eusername = eusername.(string)
	} else {
		eu, err := user.LookupId(proc.EUID)
		if err == nil {
			proc.Eusername = eu.Username
			if euid, err := strconv.Atoi(proc.EUID); err == nil {
				global.UsernameCache.Store(euid, eu.Username)
			}
		}
	}

	// inodes 于 fd 关联, 获取 remote_ip
	inodes := make(map[uint32]string)
	if sockets, err := network.ParseProcNet(unix.AF_INET, unix.IPPROTO_TCP, "/proc/"+fmt.Sprint(pid)+"/net/tcp", network.TCP_ESTABLISHED); err == nil {
		for _, socket := range sockets {
			if socket.Inode != 0 {
				if socket.DIP.String() == "0.0.0.0" {
					continue
				}
				inodes[socket.Inode] = string(socket.DIP.String()) + ":" + fmt.Sprint(socket.DPort)
			}
		}
	}

	fds, _ := process.FileDescriptorTargets()
	for _, fd := range fds {
		if strings.HasPrefix(fd, "socket:[") {
			inode, _ := strconv.ParseUint(strings.TrimRight(fd[8:], "]"), 10, 32)
			d, ok := inodes[uint32(inode)]
			if ok {
				if proc.RemoteAddrs == "" {
					proc.RemoteAddrs = d
				} else if strings.Contains(proc.RemoteAddrs, d) {
					continue
				}
				proc.RemoteAddrs = proc.RemoteAddrs + "," + d
			}
		}
	}

	return proc, nil
}

func ProcessUpdateJob() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			Singleton.FlushProcessCache()
		case <-global.Context.Done():
			return
		}
	}
}
