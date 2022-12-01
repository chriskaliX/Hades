package process

import (
	"collector/cache/user"
	"collector/share"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const maxPidTrace = 4

func GetFds(pid int) ([]string, error) {
	fds, err := os.ReadDir("/proc/" + strconv.Itoa(int(pid)) + "/fd")
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, 4)
	for index, fd := range fds {
		// In some peticular situation, count of fd over 100k, limit for this
		if index > 100 {
			break
		}
		file, err := os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/fd/" + fd.Name())
		if err != nil {
			// skip error(better use for sockets)
			continue
		}
		files = append(files, file)
	}
	return files, nil
}

func getFd(pid int, index int) (string, error) {
	file, err := os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/fd/" + strconv.Itoa(index))
	if len(file) > maxCmdline {
		file = file[:maxCmdline-1]
	}
	return file, err
}

func GetPids(limit int) (pids []int, err error) {
	pids = make([]int, 0, 100)
	d, err := os.Open("/proc")
	if err != nil {
		return
	}
	names, err := d.Readdirnames(limit + 128)
	if err != nil {
		return
	}
	for _, name := range names {
		if limit == 0 {
			return
		}
		pid, err := strconv.ParseInt(name, 10, 64)
		if err == nil {
			pids = append(pids, int(pid))
			limit -= 1
		}
	}
	return
}

// get single process information by it's pid
func GetProcessInfo(pid int, simple bool) (proc *Process, err error) {
	proc = Pool.Get()
	proc.PID = pid
	if err = proc.GetStatus(); err != nil {
		return
	}
	if err = proc.GetCwd(); err != nil {
		return
	}
	if err = proc.GetCmdline(); err != nil {
		return
	}
	if err = proc.GetExe(); err != nil {
		return
	}
	if err = proc.GetComm(); err != nil {
		return
	}
	if err = proc.GetNs(); err != nil {
		return
	}

	proc.GetEnv()

	proc.Stdin, _ = getFd(proc.PID, 0)
	proc.Stdout, _ = getFd(proc.PID, 0)
	proc.Hash = share.Sandbox.GetHash(proc.Exe)
	// netlink do not get stat information
	if err = proc.GetStat(simple); err != nil {
		return
	}
	if proc.UID >= 0 {
		proc.Username = user.Cache.GetUsername(uint32(proc.UID))
	}
	if ppid, ok := PidCache.Get(pid); ok {
		proc.PPID = ppid.(int)
	}
	if argv, ok := ArgvCache.Get(proc.PPID); ok {
		proc.PpidArgv = argv.(string)
	} else {
		proc.PpidArgv, _ = getCmdline(proc.PPID)
	}

	return proc, nil
}

func GetPidTree(pid int) (pidtree string) {
	var first = true
	for i := 0; i < maxPidTrace; i++ {
		pidtree = fmt.Sprintf("%s%d.", pidtree, pid)
		if cmdline, ok := CmdlineCache.Get(pid); ok {
			pidtree = pidtree + cmdline.(string)
			goto PidLoop
		}
		// every event get one chance to flash the comm if a pid was found
		if first {
			first = false
			if comm, err := getComm(pid); err == nil {
				pidtree = pidtree + comm
				goto PidLoop
			}
		}
		break
	PidLoop:
		if pid == 0 || pid == 1 {
			break
		}
		if ppid, ok := PidCache.Get(pid); ok {
			pid = ppid.(int)
			pidtree = pidtree + "<"
		} else {
			break
		}
	}
	return strings.TrimRight(pidtree, "<")
}
