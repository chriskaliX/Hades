package event

import (
	"hades-ebpf/user/cache"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/filter/window"
	"strings"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*Execve)(nil)

type Execve struct {
	decoder.BasicEvent `json:"-"`
	Exe                string `json:"-"`
	Cwd                string `json:"cwd"`
	TTYName            string `json:"tty_name"`
	Stdin              string `json:"stdin"`
	Stdout             string `json:"stdout"`
	Dport              uint16 `json:"dport"`
	Dip                string `json:"dip"`
	Sport              uint16 `json:"sport"`
	Sip                string `json:"sip"`
	Family             uint16 `json:"family"`
	SocketPid          uint32 `json:"socket_pid"`
	SocketArgv         string `json:"socket_argv"`
	PidTree            string `json:"pid_tree"`
	Argv               string `json:"argv"`
	PrivEscalation     uint8  `json:"priv_esca"`
	SSHConnection      string `json:"ssh_connection"`
	LDPreload          string `json:"ld_preload"`
}

func (Execve) ID() uint32 {
	return 700
}

func (Execve) Name() string {
	return "execve"
}

func (e *Execve) GetExe() string {
	return e.Exe
}

func (e *Execve) DecodeEvent(decoder *decoder.EbpfDecoder) (err error) {
	var dummy uint8
	if e.Exe, err = decoder.DecodeString(); err != nil {
		return
	}
	// Dynamic window for execve
	if !window.WindowCheck(e.Exe, window.DefaultExeWindow) {
		err = ErrFilter
		return
	}
	if e.Cwd, err = decoder.DecodeString(); err != nil {
		return
	}
	if e.TTYName, err = decoder.DecodeString(); err != nil {
		return
	}
	if e.Stdin, err = decoder.DecodeString(); err != nil {
		return
	}
	if e.Stdout, err = decoder.DecodeString(); err != nil {
		return
	}
	if e.Family, e.Sport, e.Dport, e.Sip, e.Dip, err = decoder.DecodeAddr(); err != nil {
		return
	}
	if err = decoder.DecodeUint8(&dummy); err != nil {
		return
	}
	if err = decoder.DecodeUint32(&e.SocketPid); err != nil {
		return
	}
	if e.PidTree, err = decoder.DecodePidTree(&e.PrivEscalation); err != nil {
		return
	}
	var strArr []string
	if strArr, err = decoder.DecodeStrArray(); err != nil {
		return
	}
	e.Argv = strings.Join(strArr, " ")
	if !window.WindowCheck(e.Argv, window.DefaultArgvWindow) {
		err = ErrFilter
		return
	}
	var envs []string
	if envs, err = decoder.DecodeStrArray(); err != nil {
		return
	}
	for _, env := range envs {
		if strings.HasPrefix(env, "SSH_") {
			e.SSHConnection = strings.TrimPrefix(env, "SSH_CONNECTION=")
		} else if strings.HasPrefix(env, "LD_PRE") {
			e.LDPreload = strings.TrimPrefix(env, "LD_PRELOAD=")
		}
	}
	if len(e.SSHConnection) == 0 {
		e.SSHConnection = "-1"
	}
	if len(e.LDPreload) == 0 {
		e.LDPreload = "-1"
	}
	e.SocketArgv = cache.DefaultArgvCache.Get(e.SocketPid)
	return
}

func (e Execve) FillCache() {
	cache.DefaultArgvCache.Set(e.Context().Pid, e.Argv)
}

func (Execve) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "TracepointSysExecve",
			Section:          "tracepoint/syscalls/sys_enter_execve",
			EbpfFuncName:     "sys_enter_execve",
			AttachToFuncName: "sys_enter_execve",
		},
		{
			UID:              "TracepointSysExecveExit",
			Section:          "tracepoint/syscalls/sys_exit_execve",
			EbpfFuncName:     "sys_exit_execve",
			AttachToFuncName: "sys_exit_execve",
		},
	}
}

func init() {
	decoder.RegistEvent(&Execve{})
}
