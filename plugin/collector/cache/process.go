package cache

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

var DefaultProcessPool = NewPool()

type ProcessPool struct {
	p *sync.Pool
}

func NewPool() *ProcessPool {
	return &ProcessPool{p: &sync.Pool{
		New: func() interface{} {
			return &Process{}
		},
	}}
}

func (p ProcessPool) Get() *Process {
	pr := p.p.Get().(*Process)
	pr.Reset()
	return pr
}

func (p ProcessPool) Put(pr *Process) {
	p.p.Put(pr)
}

var emptyProcess = &Process{}

// process 定期采集的进程, cn_proc/ebpf 采集的进程, 共用这个结构体
type Process struct {
	CgroupId        int    `json:"cgroupid,omitempty"`
	Uts_inum        int    `json:"uts_inum,omitempty"`
	PID             int    `json:"pid"`
	TID             int    `json:"tid,omitempty"`
	PPID            int    `json:"ppid"`
	Name            string `json:"name"`
	PName           string `json:"pname,omitempty"`
	Cmdline         string `json:"cmdline"`
	Exe             string `json:"exe"`
	Sha256          string `json:"sha256"`
	UID             string `json:"uid"`
	Username        string `json:"username"`
	EUID            string `json:"euid"`
	Eusername       string `json:"eusername"`
	Cwd             string `json:"cwd"`
	Session         int    `json:"session"`
	TTY             int    `json:"tty,omitempty"`
	TTYName         string `json:"ttyname,omitempty"`
	StartTime       uint64 `json:"starttime"`
	RemoteAddr      string `json:"remoteaddr,omitempty"`
	RemotePort      string `json:"remoteport,omitempty"`
	LocalAddr       string `json:"localaddr,omitempty"`
	LocalPort       string `json:"localport,omitempty"`
	PidTree         string `json:"pidtree,omitempty"`
	Source          string `json:"source"`
	Syscall         string `json:"syscall,omitempty"`
	RetVal          int    `json:"retval"`
	NodeName        string `json:"nodename"`
	Stdin           string `json:"stdin,omitempty"`
	Stdout          string `json:"stdout,omitempty"`
	LD_Preload      string `json:"ld_preload,omitempty"`
	LD_Library_Path string `json:"ld_library_path,omitempty"`
	SSH_connection  string `json:"ssh_connection,omitempty"`
	Utime           uint64 `json:"utime,omitempty"`
	Stime           uint64 `json:"stime,omitempty"`
	Rss             uint64 `json:"resmem,omitempty"`
	Vsize           uint64 `json:"virmem,omitempty"`
	Cpu             string `json:"cpu,omitempty"`
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
			p.UID = fields[1]
			p.EUID = fields[2]
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
	p.Cwd, err = os.Readlink("/proc/" + strconv.Itoa(int(p.PID)) + "/exe")
	return
}

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
	return
}

// TODO: unfinished with CPUPercentage. And FDs havn't go through
// the format of `stat`:
// @Reference: https://stackoverflow.com/questions/39066998/what-are-the-meaning-of-values-at-proc-pid-stat
func (p *Process) GetStat() (err error) {
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

	// iotime := uint64(0)
	// if len(fields) > 42 {
	// 	iotime, _ = strconv.ParseUint(string(fields[42]), 10, 64)
	// }
	// createTime := ((p.StartTime / SC_CLK_TCK) + _bootTime) * 1000
	// totalTime := time.Since(createTime).Seconds()
	// user := p.Utime / SC_CLK_TCK
	// system := p.Stime / SC_CLK_TCK
	// iowait := iotime / SC_CLK_TCK
	// cpuTotal := user + system + iowait
	// cpu := 100 * cpuTotal / totalTime
	// // for collection, add rt as well maybe
	return
}

func (p *Process) Reset() {
	*p = *emptyProcess
}

func GetFds(pid int) ([]string, error) {
	fds, err := os.ReadDir("/proc/" + strconv.Itoa(int(pid)) + "/fd")
	if err != nil {
		return nil, err
	}
	files := []string{}
	for _, fd := range fds {
		file, err := os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/fd/" + fd.Name())
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}
