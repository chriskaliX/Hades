package event

import (
	"hades-ebpf/userspace/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultMemfdCreate = &MemfdCreate{}

var _ decoder.Event = (*MemfdCreate)(nil)

type MemfdCreate struct {
	Exe   string `json:"-"`
	Uname string `json:"uname"`
	Flags uint32 `json:"flags"`
}

func (MemfdCreate) ID() uint32 {
	return 614
}

func (MemfdCreate) String() string {
	return "memfd_create"
}

func (m *MemfdCreate) GetExe() string {
	return m.Exe
}

func (m *MemfdCreate) Parse() (err error) {
	var index uint8
	if m.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if m.Uname, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint32(&m.Flags); err != nil {
		return
	}
	return
}

func (m *MemfdCreate) GetProbe() *manager.Probe {
	return &manager.Probe{
		Section:      "tracepoint/syscalls/sys_enter_memfd_create",
		EbpfFuncName: "sys_enter_memfd_create",
	}
}

func init() {
	decoder.Regist(DefaultMemfdCreate)
}
