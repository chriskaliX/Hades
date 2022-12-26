package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*SysConnect)(nil)

type SysConnect struct {
	Family uint16 `json:"family"`
	Dport  uint16 `json:"dport"`
	Dip    string `json:"dip"`
	Sport  uint16 `json:"sport"`
	Sip    string `json:"sip"`
	Exe    string `json:"-"`
}

func (SysConnect) ID() uint32 {
	return 1022
}

func (SysConnect) Name() string {
	return "sys_connect"
}

func (s *SysConnect) GetExe() string {
	return s.Exe
}

func (s *SysConnect) DecodeEvent(decoder *decoder.EbpfDecoder) (err error) {
	if s.Family, s.Sport, s.Dport, s.Sip, s.Dip, err = decoder.DecodeAddr(); err != nil {
		return
	}
	s.Exe, err = decoder.DecodeString()
	return
}

func (SysConnect) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "tracepoint_sys_enter_connect",
			Section:          "tracepoint/syscalls/sys_enter_connect",
			EbpfFuncName:     "sys_enter_connect",
			AttachToFuncName: "sys_enter_connect",
		},
		{
			UID:              "tracepoint_sys_exit_connect",
			Section:          "tracepoint/syscalls/sys_exit_connect",
			EbpfFuncName:     "sys_exit_connect",
			AttachToFuncName: "sys_exit_connect",
		},
	}
}

func (s *SysConnect) GetMaps() []*manager.Map { return nil }

func (SysConnect) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() {
	decoder.RegistEvent(&SysConnect{})
}
