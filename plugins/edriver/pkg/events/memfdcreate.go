package event

import (
	"edriver/pkg/decoder"

	manager "github.com/gojue/ebpfmanager"
)

var _ decoder.Event = (*MemfdCreate)(nil)

type MemfdCreate struct {
	Exe   string `json:"-"`
	Uname string `json:"uname"`
	Flags uint32 `json:"flags"`
}

func (MemfdCreate) ID() uint32 {
	return 614
}

func (MemfdCreate) Name() string {
	return "memfd_create"
}

func (m *MemfdCreate) GetExe() string {
	return m.Exe
}

func (m *MemfdCreate) DecodeEvent(decoder *decoder.EbpfDecoder) (err error) {
	var index uint8
	if m.Exe, err = decoder.DecodeString(); err != nil {
		return
	}
	if m.Uname, err = decoder.DecodeString(); err != nil {
		return
	}
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeUint32(&m.Flags); err != nil {
		return
	}
	return
}

func (m *MemfdCreate) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "TpSysEnterMemfdCreate",
			Section:          "tracepoint/syscalls/sys_enter_memfd_create",
			EbpfFuncName:     "sys_enter_memfd_create",
			AttachToFuncName: "sys_enter_memfd_create",
		},
	}
}

func (m *MemfdCreate) GetMaps() []*manager.Map { return nil }

func (MemfdCreate) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() {
	decoder.RegistEvent(&MemfdCreate{})
}
