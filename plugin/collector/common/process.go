package common

type Process struct {
	CID         int    `json:"cid,omitempty"`
	PID         int    `json:"pid"`
	TID         int    `json:"tid,omitempty"`
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
	StartTime   uint64 `json:"starttime"`
	RemoteAddrs string `json:"remoteaddrs"`
	PidTree     string `json:"pidtree"`
	Source      string `json:"source"`
	Syscall     string `json:"syscall,omitempty"`
	// Only valid when processes ticker collector
	ResMem string `json:"resmem,omitempty"`
	VirMem string `json:"virmem,omitempty"`
	Cpu    string `json:"cpu,omitempty"`
	// 缺失部分
	/*
		sid
		nodename
		pns
		root_pns
		exe_size
	*/
}
