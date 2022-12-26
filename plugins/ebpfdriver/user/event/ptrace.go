package event

import (
	"hades-ebpf/user/decoder"

	"github.com/chriskaliX/SDK/config"
	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*Ptrace)(nil)

type Ptrace struct {
	Exe            string `json:"-"`
	Requests       int64  `json:"request"`
	TargetPid      int64  `json:"targetpid"`
	Addr           uint64 `json:"addr"`
	PidTree        string `json:"pid_tree"`
	PrivEscalation uint8  `json:"priv_esca"`
}

func (Ptrace) ID() uint32 {
	return config.DTPtrace
}

func (Ptrace) Name() string {
	return "ptrace"
}

func (p *Ptrace) GetExe() string {
	return p.Exe
}

func (p *Ptrace) DecodeEvent(decoder *decoder.EbpfDecoder) (err error) {
	if p.Exe, err = decoder.DecodeString(); err != nil {
		return
	}
	var index uint8
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeInt64(&p.Requests); err != nil {
		return
	}
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeInt64(&p.TargetPid); err != nil {
		return
	}
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeUint64(&p.Addr); err != nil {
		return
	}
	if p.PidTree, err = decoder.DecodePidTree(&p.PrivEscalation); err != nil {
		return
	}
	return
}

func (Ptrace) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "TpSysEnterPtrace",
			Section:          "tracepoint/syscalls/sys_enter_ptrace",
			EbpfFuncName:     "sys_enter_ptrace",
			AttachToFuncName: "sys_enter_ptrace",
		},
	}
}

func (p *Ptrace) GetMaps() []*manager.Map { return nil }

func (Ptrace) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() {
	decoder.RegistEvent(&Ptrace{})
}
