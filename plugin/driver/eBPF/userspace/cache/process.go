package cache

import (
	"os"
	"strconv"
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
	CgroupId        uint64 `json:"cgroupid,omitempty"`
	Uts_inum        uint32 `json:"uts_inum,omitempty"`
	PID             uint32 `json:"pid"`
	TID             uint32 `json:"tid,omitempty"`
	PPID            uint32 `json:"ppid"`
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
	RetVal          uint64 `json:"retval"`
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
	Prctl_Option    int32  `json:"prctl_option,omitempty"`
	Prctl_Newname   string `json:"prctl_newname,omitempty"` //just for test,
	Prctl_Flag      uint32 `json:"prctl_flag,omitempty"`
}

func (p *Process) GetCwd() (err error) {
	p.Cwd, err = os.Readlink("/proc/" + strconv.Itoa(int(p.PID)) + "/cwd")
	return
}

func (p *Process) GetExe() (err error) {
	p.Cwd, err = os.Readlink("/proc/" + strconv.Itoa(int(p.PID)) + "/exe")
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
