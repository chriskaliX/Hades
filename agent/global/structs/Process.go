package structs

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
