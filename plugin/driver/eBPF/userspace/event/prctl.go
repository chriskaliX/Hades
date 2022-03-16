package event

import (
	"hades-ebpf/userspace/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultPrctl = &Prctl{}

var _ decoder.Event = (*Prctl)(nil)

type Prctl struct {
	Exe     string `json:"-"`
	Option  string `json:"option"`
	Newname string `json:"newname,omitempty"`
	Flag    uint32 `json:"flag,omitempty"`
}

func (Prctl) ID() uint32 {
	return 200
}

func (Prctl) String() string {
	return "prctl"
}

func (e *Prctl) GetExe() string {
	return e.Exe
}

func (p *Prctl) Parse() (err error) {
	var index uint8
	var option int32
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt32(&option); err != nil {
		return
	}
	if p.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	switch option {
	case 15:
		p.Option = "PR_SET_NAME"
		if p.Newname, err = decoder.DefaultDecoder.DecodeString(); err != nil {
			return
		}
	case 35:
		p.Option = "PR_SET_MM"
		if err = decoder.DefaultDecoder.DecodeUint32(&p.Flag); err != nil {
			return
		}
	}
	return
}

func (Prctl) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			Section:      "tracepoint/syscalls/sys_enter_prctl",
			EbpfFuncName: "sys_enter_prctl",
		},
	}
}

func init() {
	decoder.Regist(DefaultPrctl)
}
