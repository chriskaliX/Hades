package process

import (
	"collector/cache/user"
	"collector/utils"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/chriskaliX/SDK/utils/hash"
)

var HashCache = hash.NewWithClock(utils.Clock)

func GetFds(pid int) (result []string, err error) {
	var f *os.File
	f, err = os.Open(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return
	}
	defer f.Close()
	var names []string
	names, err = f.Readdirnames(1024)
	if err != nil {
		return
	}
	for _, name := range names {
		res, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", name))
		if err != nil {
			continue
		}
		result = append(result, strings.TrimSpace(res))
	}
	return
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
	proc = &Process{}
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
	proc.Hash = HashCache.GetHash(proc.Exe)
	// netlink do not get stat information
	if err = proc.GetStat(simple); err != nil {
		return
	}
	if proc.UID >= 0 {
		u := user.Cache.GetUser(uint32(proc.UID))
		proc.Username = u.Username
		gid, _ := strconv.ParseInt(u.GID, 10, 32)
		proc.GID = int(gid)
	}
	if ppid, ok := PidCache.Get(pid); ok {
		proc.PPID = ppid.(int)
	}
	// ppid argv
	if argv, ok := ArgvCache.Get(proc.PPID); ok {
		proc.PpidArgv = argv.(string)
	} else {
		proc.PpidArgv, _ = getCmdline(proc.PPID)
	}
	// pgid argv
	if argv, ok := ArgvCache.Get(proc.PGID); ok {
		proc.PgidArgv = argv.(string)
	} else {
		proc.PgidArgv, _ = getCmdline(proc.PGID)
	}

	return proc, nil
}
