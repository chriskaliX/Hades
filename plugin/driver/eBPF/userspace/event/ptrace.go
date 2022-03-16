package event

import (
	"hades-ebpf/userspace/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultPtrace = &Ptrace{}

var _ decoder.Event = (*Ptrace)(nil)

type Ptrace struct {
	Exe       string `json:"-"`
	Requests  int64  `json:"request"`
	TargetPid int64  `json:"targetpid"`
	Addr      uint64 `json:"addr"`
	PidTree   string `json:"pidtree"`
}

func (Ptrace) ID() uint32 {
	return 164
}

func (Ptrace) String() string {
	return "ptrace"
}

func (p *Ptrace) GetExe() string {
	return p.Exe
}

func (p *Ptrace) Parse() (err error) {
	if p.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	var index uint8
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt64(&p.Requests); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt64(&p.TargetPid); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint64(&p.Addr); err != nil {
		return
	}
	if p.PidTree, err = decoder.DefaultDecoder.DecodePidTree(); err != nil {
		return
	}
	return
}

func (Ptrace) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			Section:      "tracepoint/syscalls/sys_enter_ptrace",
			EbpfFuncName: "sys_enter_ptrace",
		},
	}
}

func init() {
	decoder.Regist(DefaultPtrace)
}
