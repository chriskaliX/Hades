package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultPrctl = &Prctl{}

var _ decoder.Event = (*Prctl)(nil)

type Prctl struct {
	decoder.BasicEvent `json:"-"`
	Exe                string `json:"-"`
	Option             string `json:"option"`
	Newname            string `json:"newname,omitempty"`
	Flag               uint32 `json:"flag,omitempty"`
}

func (Prctl) ID() uint32 {
	return 200
}

func (Prctl) Name() string {
	return "prctl"
}

func (e *Prctl) GetExe() string {
	return e.Exe
}

func (p *Prctl) DecodeEvent(decoder *decoder.EbpfDecoder) (err error) {
	var index uint8
	var option int32
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeInt32(&option); err != nil {
		return
	}
	if p.Exe, err = decoder.DecodeString(); err != nil {
		return
	}
	switch option {
	case 15:
		p.Option = "PR_SET_NAME"
		if p.Newname, err = decoder.DecodeString(); err != nil {
			return
		}
	case 35:
		p.Option = "PR_SET_MM"
		if err = decoder.DecodeUint32(&p.Flag); err != nil {
			return
		}
	}
	return
}

func (Prctl) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "TpSysEnterPrctl",
			Section:          "tracepoint/syscalls/sys_enter_prctl",
			EbpfFuncName:     "sys_enter_prctl",
			AttachToFuncName: "sys_enter_prctl",
		},
	}
}

func init() {
	decoder.DefaultEventCollection.Regist(DefaultPrctl)
}
