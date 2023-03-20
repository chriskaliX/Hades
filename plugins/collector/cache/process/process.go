package process

import (
	"bufio"
	"bytes"
	"collector/cache"
	ns "collector/cache/namespace"
	"collector/utils"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type Process struct {
	Pns      int    `json:"pns"`
	RootPns  int    `json:"root_pns"`
	PID      int    `json:"pid"`
	GID      int    `json:"gid"`
	PGID     int    `json:"pgid"`
	PgidArgv string `json:"pgid_argv,omitempty"`
	TID      int    `json:"tid,omitempty"`
	Session  int    `json:"session"`
	PPID     int    `json:"ppid"`
	PpidArgv string `json:"ppid_argv,omitempty"`
	Name     string `json:"name"`
	Argv     string `json:"argv"`
	Exe      string `json:"exe"`
	Hash     string `json:"exe_hash"`
	UID      int32  `json:"uid"`
	Username string `json:"username"`
	Cwd      string `json:"cwd"`
	Stdin    string `json:"stdin"`
	Stdout   string `json:"stdout"`
	PidTree  string `json:"pid_tree,omitempty"`
	PodName  string `json:"pod_name"`
	NodeName string `json:"nodename"`

	TTY        int     `json:"tty,omitempty"`
	TTYName    string  `json:"ttyname,omitempty"`
	StartTime  uint64  `json:"start_time,omitempty"`
	RemoteAddr string  `json:"remoteaddr,omitempty"`
	RemotePort string  `json:"remoteport,omitempty"`
	LocalAddr  string  `json:"localaddr,omitempty"`
	LocalPort  string  `json:"localport,omitempty"`
	Utime      uint64  `json:"utime,omitempty"`
	Stime      uint64  `json:"stime,omitempty"`
	Rss        uint64  `json:"resmem,omitempty"`
	Vsize      uint64  `json:"virmem,omitempty"`
	Cpu        float64 `json:"cpu,omitempty"`
}

// In promthues/procfs, it returns out that in every disros that they researched, USER_HZ
// is actually hardcoded to 100 on all Go-supported platforms. See the reference here:
// https://github.com/prometheus/procfs/blob/116b5c4f80ab09a0a6a848a7606652821b90d065/proc_stat.go
// https://github.com/mneverov/CPUStat
// the author claims that it is safe to hardcode this to 100
const userHz = 100
const maxCmdline = 8 * 1024 // Large since java cmdline is loooog

// internal system related variables
var bootTime = uint64(0)
var sysTime = uint64(0)
var nproc = runtime.NumCPU()

// readonly, change to readfile
func (p *Process) GetStatus() (err error) {
	var file *os.File
	if file, err = os.Open("/proc/" + strconv.Itoa(p.PID) + "/status"); err != nil {
		return
	}
	defer file.Close()
	s := bufio.NewScanner(file)
	for s.Scan() {
		if strings.HasPrefix(s.Text(), "Name:") {
			p.Name = strings.Fields(s.Text())[1]
		} else if strings.HasPrefix(s.Text(), "Uid:") {
			fields := strings.Fields(s.Text())
			p.UID = utils.ParseInt32(fields[1])
			break
		}
	}
	return
}

func (p *Process) GetCwd() (err error) {
	p.Cwd, err = os.Readlink("/proc/" + strconv.Itoa(int(p.PID)) + "/cwd")
	return
}

func (p *Process) GetExe() (err error) {
	p.Exe, err = os.Readlink("/proc/" + strconv.Itoa(int(p.PID)) + "/exe")
	return
}

func (p *Process) GetCmdline() (err error) {
	p.Argv, err = getCmdline(p.PID)
	return
}

func (p *Process) Fds() (result []string, err error) {
	return GetFds(p.PID)
}

// The one and only real function of get cmdline, cache will be filled automatically
func getCmdline(pid int) (cmdline string, err error) {
	if pid == 1<<32-1 {
		cmdline = "-1"
	} else {
		var res []byte
		if res, err = os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline"); err != nil {
			return
		}
		if len(res) == 0 {
			return
		}
		res = bytes.ReplaceAll(res, []byte{0}, []byte{' '})
		res = bytes.TrimSpace(res)
		cmdline = string(res)
		if len(cmdline) > maxCmdline {
			cmdline = cmdline[:maxCmdline]
		}
	}
	ArgvCache.Add(pid, cmdline)
	return
}

func (p *Process) GetComm() (err error) {
	p.Name, err = getComm(p.PID)
	return
}

func getComm(pid int) (comm string, err error) {
	var res []byte
	if res, err = os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err != nil {
		return
	}
	if len(res) == 0 {
		return
	}
	res = bytes.TrimSpace(res)
	comm = string(res)
	CmdlineCache.Add(pid, comm)
	return
}

func (p *Process) GetNs() error {
	pns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", p.PID))
	if err != nil {
		return err
	}
	if len(pns) >= 6 {
		p.Pns, _ = strconv.Atoi(pns[5 : len(pns)-1])
	}
	return nil
}

func (p *Process) GetEnv() {
	p.PodName, p.NodeName = ns.Cache.Get(uint32(p.PID), uint32(p.Pns))
}

func (p *Process) GetStat(simple bool) (err error) {
	var stat []byte
	if stat, err = os.ReadFile("/proc/" + strconv.Itoa(p.PID) + "/stat"); err != nil {
		return
	}
	statStr := string(stat)
	fields := strings.Fields(statStr)
	if len(fields) < 24 {
		err = errors.New("invalid stat format")
		return
	}
	if len(fields[1]) > 1 {
		p.Name = string(fields[1][1 : len(fields[1])-1])
	}
	p.PPID, _ = strconv.Atoi(fields[3])
	p.PGID, _ = strconv.Atoi(fields[7])
	p.Session, _ = strconv.Atoi(fields[5])
	p.TTY, _ = strconv.Atoi(fields[6])
	if simple {
		return
	}
	p.Utime, _ = strconv.ParseUint(fields[13], 10, 64)
	p.Stime, _ = strconv.ParseUint(fields[14], 10, 64)
	p.StartTime, _ = strconv.ParseUint(fields[21], 10, 64)
	p.Vsize, _ = strconv.ParseUint(fields[22], 10, 64)
	p.Rss, _ = strconv.ParseUint(fields[23], 10, 64)
	// for cpu usage, it defer from answer to answer
	// @Reference:
	// https://stackoverflow.com/questions/16726779/how-do-i-get-the-total-cpu-usage-of-an-application-from-proc-pid-stat#
	// https://github.com/mneverov/CPUStat
	// nproc not found and understood
	// https://github.com/prometheus/procfs
	p.StartTime = bootTime + (p.StartTime / userHz)
	// iotime in mneverov/CPUStat
	iotime := uint64(0)
	if len(fields) > 42 {
		iotime, _ = strconv.ParseUint(string(fields[42]), 10, 64)
	}
	p.Cpu = (float64((p.Utime + p.Stime + iotime)) / float64(sysTime)) * float64(nproc)
	p.Cpu, _ = strconv.ParseFloat(fmt.Sprintf("%.6f", p.Cpu), 64)
	return
}

func (p *Process) IsContainer() bool {
	if p.Pns == 0 {
		return false
	}
	return p.Pns != cache.RootPns
}

func init() {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer file.Close()
	s := bufio.NewScanner(file)
	t := uint64(0)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if t == 0 {
			for i, f := range fields {
				if i == 8 {
					break
				}
				u, _ := strconv.ParseUint(f, 10, 64)
				t += u
			}
			sysTime = t
		}
		if !strings.HasPrefix(s.Text(), "btime") {
			continue
		}
		if len(fields) < 2 {
			continue
		}
		bootTime, _ = strconv.ParseUint(fields[1], 10, 64)
	}
}
