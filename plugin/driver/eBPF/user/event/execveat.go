package event

import (
	"hades-ebpf/user/cache"
	"hades-ebpf/user/decoder"
	"strings"

	manager "github.com/ehids/ebpfmanager"
	"go.uber.org/zap"
)

var DefaultExecveAt = &ExecveAt{}

var _ decoder.Event = (*ExecveAt)(nil)

type ExecveAt struct {
	decoder.BasicEvent `json:"-"`
	Exe                string `json:"-"`
	Cwd                string `json:"cwd"`
	TTYName            string `json:"tty_name"`
	Stdin              string `json:"stdin"`
	Stdout             string `json:"stdout"`
	Dport              string `json:"dport"`
	Dip                string `json:"dip"`
	PidTree            string `json:"pid_tree"`
	Argv               string `json:"argv"`
	PrivEscalation     uint8  `json:"priv_esca"`
	SSHConnection      string `json:"ssh_connection"`
	LDPreload          string `json:"ld_preload"`
}

func (ExecveAt) ID() uint32 {
	return 698
}

func (ExecveAt) String() string {
	return "execveat"
}

func (e *ExecveAt) GetExe() string {
	return e.Exe
}

func (e *ExecveAt) Parse() (err error) {
	if e.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if e.Cwd, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if e.TTYName, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if e.Stdin, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if e.Stdout, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if e.Dport, e.Dip, err = decoder.DefaultDecoder.DecodeRemoteAddr(); err != nil {
		return
	}
	if e.PidTree, err = decoder.DefaultDecoder.DecodePidTree(&e.PrivEscalation); err != nil {
		return
	}
	var strArr []string
	if strArr, err = decoder.DefaultDecoder.DecodeStrArray(); err != nil {
		zap.S().Error("execveat cmdline error")
		return
	}
	e.Argv = strings.Join(strArr, " ")
	envs := make([]string, 0, 3)
	if envs, err = decoder.DefaultDecoder.DecodeStrArray(); err != nil {
		return
	}
	for _, env := range envs {
		if strings.HasPrefix(env, "SSH_CONNECTION=") {
			e.SSHConnection = strings.TrimLeft(env, "SSH_CONNECTION=")
		} else if strings.HasPrefix(env, "LD_PRELOAD=") {
			e.LDPreload = strings.TrimLeft(env, "LD_PRELOAD=")
		}
	}
	if len(e.SSHConnection) == 0 {
		e.SSHConnection = "-1"
	}
	if len(e.LDPreload) == 0 {
		e.LDPreload = "-1"
	}
	return
}

func (ExecveAt) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "TracepointSysExecveat",
			Section:          "tracepoint/syscalls/sys_enter_execveat",
			EbpfFuncName:     "sys_enter_execveat",
			AttachToFuncName: "sys_enter_execveat",
		},
		{
			UID:              "TracepointSysExecveatExit",
			Section:          "tracepoint/syscalls/sys_exit_execveat",
			EbpfFuncName:     "sys_exit_execveat",
			AttachToFuncName: "sys_exit_execveat",
		},
	}
}

func (e ExecveAt) FillContext(pid uint32) {
	cache.DefaultArgvCache.Put(pid, e.Argv)
}

func init() {
	decoder.Regist(DefaultExecveAt)
}
