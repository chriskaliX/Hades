package structs

import "sync"

var ProcessPool *sync.Pool

type Process struct {
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid"`
	Name        string `json:"name"`
	Cmdline     string `json:"cmdline"`
	Exe         string `json:"exe"`
	Sha256      string `json:"sha256"`
	UID         string `json:"uid"`
	Username    string `json:"username"`
	EUID        string `json:"euid"`
	Eusername   string `json:"eusername"`
	Cwd         string `json:"cwd"`
	Session     int    `json:"session"`
	TTY         int    `json:"tty"`
	StartTime   uint64 `json:"start_time"`
	RemoteAddrs string `json:"RemoteAddrs"`
	PsTree      string `json:"PsTree"`
}

func (p *Process) Reset() {
	p.PID = 0
	p.PPID = 0
	p.Name = ""
	p.Cmdline = ""
	p.Exe = ""
	p.Sha256 = ""
	p.UID = ""
	p.EUID = ""
	p.Eusername = ""
	p.Cwd = ""
	p.Session = 0
	p.TTY = 0
	p.StartTime = 0
	p.RemoteAddrs = ""
	p.PsTree = ""
}

func init() {
	ProcessPool = &sync.Pool{
		New: func() interface{} {
			return new(Process)
		},
	}
}
