package structs

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

var ProcessPool *sync.Pool

// process 定期采集的进程, cn_proc/ebpf 采集的进程, 共用这个结构体
type Process struct {
	CgroupId        int    `json:"cgroupid,omitempty"`
	Uts_inum        int    `json:"uts_inum"`
	Parent_uts_inum int    `json:"parent_uts_inum"`
	PID             int    `json:"pid"`
	TID             int    `json:"tid,omitempty"`
	PPID            int    `json:"ppid"`
	Name            string `json:"name"`
	PName           string `json:"pname"`
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
	TTYName         string `json:"ttyname"`
	StartTime       uint64 `json:"starttime"`
	RemoteAddrs     string `json:"remoteaddrs"`
	PidTree         string `json:"pidtree"`
	Source          string `json:"source"`
	Syscall         string `json:"syscall,omitempty"`
	NodeName        string `json:"nodename"`
	LD_Preload      string `json:"ld_preload"`
	// Only valid when processes ticker collector
	ResMem string `json:"resmem,omitempty"`
	VirMem string `json:"virmem,omitempty"`
	Cpu    string `json:"cpu,omitempty"`
}

/*
	// 优化点 1:
	// 这里有点问题, 压测了一下观察火焰图, 这里耗时非常高, 占比 Collector 的近 40%, 更改后占 20% 多
	// 我们跟进去看一下, 是一次性读取之后全部 load 进来, 由于我们只需要获取部分数据
	// 不需要全部读取, 读取到特定行之后退出即可
	// status, err := process.NewStatus()
	// if err == nil {
	// 	proc.UID = status.UIDs[0]
	// 	proc.EUID = status.UIDs[1]
	// 	proc.Name = status.Name
	// }
*/
// 因为我们不需要读取全部信息, 读取到需要的行之后直接退出
// 用来加速, 不直接创建对象
func (p *Process) NameUidEuid() {
	if p == nil {
		return
	}
	path := "/proc/" + strconv.Itoa(p.PID) + "/status"
	if file, err := os.Open(path); err == nil {
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
	}
}

var emptyProcess = &Process{}

func (p *Process) Reset() {
	*p = *emptyProcess
}

func init() {
	ProcessPool = &sync.Pool{
		New: func() interface{} {
			return Process{}
		},
	}
}
