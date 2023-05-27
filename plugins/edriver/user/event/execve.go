package event

import (
	"hades-ebpf/user/cache"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/filter/window"
	"reflect"
	"strings"

	"github.com/bytedance/sonic"
	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*Execve)(nil)

type Execve struct {
	Exe            string `json:"-"`
	Cwd            string `json:"cwd"`
	TTYName        string `json:"tty_name"`
	Stdin          string `json:"stdin"`
	Stdout         string `json:"stdout"`
	Dport          uint16 `json:"dport"`
	Dip            string `json:"dip"`
	Sport          uint16 `json:"sport"`
	Sip            string `json:"sip"`
	Family         uint16 `json:"family"`
	SocketPid      uint32 `json:"socket_pid"`
	SocketArgv     string `json:"socket_argv"`
	PidTree        string `json:"pid_tree"`
	Argv           string `json:"argv"`
	PrivEscalation uint8  `json:"priv_esca"`
	SSHConnection  string `json:"ssh_connection"`
	LDPreload      string `json:"ld_preload"`
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

func (e *Execve) DecodeEvent(d *decoder.EbpfDecoder) (err error) {
	var dummy uint8
	if e.Exe, err = d.DecodeString(); err != nil {
		return
	}
	// Dynamic window for execve
	if !window.WindowCheck(e.Exe, window.DefaultExeWindow) {
		err = decoder.ErrFilter
		return
	}
	if e.Cwd, err = d.DecodeString(); err != nil {
		return
	}
	if e.TTYName, err = d.DecodeString(); err != nil {
		return
	}
	if e.Stdin, err = d.DecodeString(); err != nil {
		return
	}
	if e.Stdout, err = d.DecodeString(); err != nil {
		return
	}
	if e.Family, e.Sport, e.Dport, e.Sip, e.Dip, err = d.DecodeAddr(); err != nil {
		return
	}
	if err = d.DecodeUint8(&dummy); err != nil {
		return
	}
	if err = d.DecodeUint32(&e.SocketPid); err != nil {
		return
	}
	if e.PidTree, err = d.DecodePidTree(&e.PrivEscalation); err != nil {
		return
	}
	var strArr []string
	if strArr, err = d.DecodeStrArray(); err != nil {
		return
	}
	e.Argv = strings.Join(strArr, " ")
	// Add the pid into argv
	cache.DefaultArgvCache.Set(d.GetContext().Pid, e.Argv)
	if !window.WindowCheck(e.Argv, window.DefaultArgvWindow) {
		err = decoder.ErrFilter
		return
	}
	var envs []string
	if envs, err = d.DecodeStrArray(); err != nil {
		return
	}
	e.SSHConnection = "-1"
	e.LDPreload = "-1"
	for _, env := range envs {
		if strings.HasPrefix(env, "SSH_") {
			e.SSHConnection = strings.TrimPrefix(env, "SSH_CONNECTION=")
		} else if strings.HasPrefix(env, "LD_PRE") {
			e.LDPreload = strings.TrimPrefix(env, "LD_PRELOAD=")
		}
	}
	e.SocketArgv = cache.DefaultArgvCache.Get(e.SocketPid)
	return
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

func (Execve) GetMaps() []*manager.Map { return nil }

func (Execve) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() {
	var execve Execve
	sonic.Pretouch(reflect.TypeOf(execve))
	decoder.RegistEvent(&Execve{})
}
