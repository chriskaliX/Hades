// Process contains a process pool and the operation of getting
// information of a process.
//
// TODO: compatible in windows
package cache

import (
	"bufio"
	"bytes"
	"collector/share"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxCmdline setting
const maxCmdline = 256

// In promthues/procfs, it returns out
// that in every disros that they researched, USER_HZ is actually hardcoded to
// 100 on all Go-supported platforms. See the reference here:
// https://github.com/prometheus/procfs/blob/116b5c4f80ab09a0a6a848a7606652821b90d065/proc_stat.go
// Also in https://github.com/mneverov/CPUStat, the author claims that it is safe to hardcode
// this to 100
const userHz = 100

// internal system related variables
var bootTime = uint64(0)
var sysTime = uint64(0)
var nproc = runtime.NumCPU()

func init() {
	stat, err := os.ReadFile("/proc/stat")
	if err == nil {
		statStr := string(stat)
		lines := strings.Split(statStr, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "btime") {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				bootTime, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}
}

var DProcessPool = NewPool()

// ProcessPool
//
// Get() get a process from the process pool
// Put() returns the process into the pool
type ProcessPool struct {
	p sync.Pool
}

func NewPool() *ProcessPool {
	return &ProcessPool{p: sync.Pool{
		New: func() interface{} {
			return &Process{}
		},
	}}
}

func (p *ProcessPool) Get() *Process {
	pr := p.p.Get().(*Process)
	return pr
}

func (p *ProcessPool) Put(pr *Process) {
	pr.CgroupId = 0
	pr.Uts_inum = 0
	pr.TID = 0
	pr.PName = ""
	pr.TTY = 0
	pr.TTYName = ""
	pr.RemoteAddr = ""
	pr.RemotePort = ""
	pr.LocalAddr = ""
	pr.LocalPort = ""
	pr.NodeName = ""
	pr.Stdin = ""
	pr.Stdout = ""
	pr.Utime = 0
	pr.Stime = 0
	pr.Rss = 0
	pr.Vsize = 0
	p.p.Put(pr)
}

// Process struct, it is shared in both process collection
// and netlink part.
type Process struct {
	CgroupId   int     `json:"cgroupid,omitempty"`
	Uts_inum   int     `json:"uts_inum,omitempty"`
	PID        int     `json:"pid"`
	TID        int     `json:"tid,omitempty"`
	PPID       int     `json:"ppid"`
	Name       string  `json:"name"`
	PName      string  `json:"pname,omitempty"`
	Cmdline    string  `json:"cmdline"`
	Exe        string  `json:"exe"`
	Hash       string  `json:"hash"`
	UID        uint32  `json:"uid"`
	Username   string  `json:"username"`
	EUID       uint32  `json:"euid"`
	Eusername  string  `json:"eusername"`
	Cwd        string  `json:"cwd"`
	Session    int     `json:"session"`
	TTY        int     `json:"tty,omitempty"`
	TTYName    string  `json:"ttyname,omitempty"`
	StartTime  uint64  `json:"starttime"`
	RemoteAddr string  `json:"remoteaddr,omitempty"`
	RemotePort string  `json:"remoteport,omitempty"`
	LocalAddr  string  `json:"localaddr,omitempty"`
	LocalPort  string  `json:"localport,omitempty"`
	PidTree    string  `json:"pidtree,omitempty"`
	Source     string  `json:"source"`
	NodeName   string  `json:"nodename,omitempty"` // TODO: support this in netlink
	Stdin      string  `json:"stdin,omitempty"`
	Stdout     string  `json:"stdout,omitempty"`
	Utime      uint64  `json:"utime,omitempty"`
	Stime      uint64  `json:"stime,omitempty"`
	Rss        uint64  `json:"resmem,omitempty"`
	Vsize      uint64  `json:"virmem,omitempty"`
	Cpu        float64 `json:"cpu,omitempty"`
}

// readonly, change to readfile
func (p *Process) GetStatus() (err error) {
	var file *os.File
	if file, err = os.Open("/proc/" + strconv.Itoa(p.PID) + "/status"); err != nil {
		return
	}
	defer file.Close()
	s := bufio.NewScanner(io.LimitReader(file, 1024*512))
	for s.Scan() {
		if strings.HasPrefix(s.Text(), "Name:") {
			p.Name = strings.Fields(s.Text())[1]
		} else if strings.HasPrefix(s.Text(), "Uid:") {
			fields := strings.Fields(s.Text())
			p.UID = share.ParseUint32(fields[1])
			p.EUID = share.ParseUint32(fields[2])
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

// In some situation, cmdline can be extremely large. A limit should
// be done here. In Elkeid LKM it's 256 as default.
func (p *Process) GetCmdline() (err error) {
	var res []byte
	if res, err = os.ReadFile("/proc/" + strconv.Itoa(p.PID) + "/cmdline"); err != nil {
		return
	}
	if len(res) == 0 {
		return
	}
	res = bytes.ReplaceAll(res, []byte{0}, []byte{' '})
	res = bytes.TrimSpace(res)
	p.Cmdline = string(res)
	if len(p.Cmdline) > maxCmdline {
		p.Cmdline = p.Cmdline[:maxCmdline]
	}
	return
}

// TODO: unfinished with CPUPercentage. And FDs havn't go through
// the format of `stat`:
// Reference: https://stackoverflow.com/questions/39066998/what-are-the-meaning-of-values-at-proc-pid-stat
func (p *Process) GetStat(simple bool) (err error) {
	var stat []byte
	if stat, err = os.ReadFile("/proc/" + strconv.Itoa(p.PID) + "/stat"); err != nil {
		return
	}
	statStr := string(stat)
	fields := strings.Fields(statStr)
	// precheck length
	if len(fields) < 24 {
		err = errors.New("invalid stat format")
		return
	}
	// wrap the `()`
	if len(fields[1]) > 1 {
		p.Name = string(fields[1][1 : len(fields[1])-1])
	}
	p.PPID, _ = strconv.Atoi(fields[3])
	p.Session, _ = strconv.Atoi(fields[5])
	p.TTY, _ = strconv.Atoi(fields[6])
	// simple
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
	// Add cutime and cstime if children processes is needed
	// Be careful with this. The cpu usage here is counted by all cpu
	total := uint64(time.Now().Unix()) - p.StartTime
	p.Cpu = ((float64((p.Utime + p.Stime + iotime)) / userHz) / float64(total))
	p.Cpu, _ = strconv.ParseFloat(fmt.Sprintf("%.6f", p.Cpu), 64)
	return
}

func GetFds(pid int) ([]string, error) {
	fds, err := os.ReadDir("/proc/" + strconv.Itoa(int(pid)) + "/fd")
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, 10)
	for _, fd := range fds {
		file, err := os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/fd/" + fd.Name())
		if err != nil {
			// skip error(better use for sockets)
			continue
		}
		files = append(files, file)
	}
	return files, nil
}

// Elkeid impletement still get problem when pid is too much, like 100,000+
func GetPids(limit int) (pids []int, err error) {
	// pre allocation
	pids = make([]int, 0, 100)
	d, err := os.Open("/proc")
	if err != nil {
		return
	}
	names, err := d.Readdirnames(limit + 50)
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
	proc = DProcessPool.Get()
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
	proc.Hash = share.Sandbox.GetHash(proc.Exe)
	if err = proc.GetStat(simple); err != nil {
		return
	}
	proc.Username = DefaultUserCache.GetUsername(proc.UID)
	proc.Eusername = DefaultUserCache.GetUsername(proc.EUID)
	// inodes 于 fd 关联, 获取 remote_ip
	// pprof 了一下, 这边占用比较大, 每个进程起来都带上 remote_addr 会导致 IO 高一点
	// 剔除了这部分对于 inodes 的关联, 默认不检测 socket 了
	return proc, nil
}
