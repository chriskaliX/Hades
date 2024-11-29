package event

import (
	"edriver/pkg/decoder"

	manager "github.com/gojue/ebpfmanager"
)

type SecurityBpf struct {
	Exe      string `json:"-"`
	Cmd      int32  `json:"cmd"`
	ProgName string `json:"name"`
	Type     uint32 `json:"type"`
}

func (SecurityBpf) ID() uint32 {
	return 1204
}

func (SecurityBpf) Name() string {
	return "security_bpf"
}

func (s *SecurityBpf) GetExe() string {
	return s.Exe
}

func (s *SecurityBpf) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	var index uint8
	if s.Exe, err = e.DecodeString(); err != nil {
		return
	}
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeInt32(&s.Cmd); err != nil {
		return
	}
	if s.ProgName, err = e.DecodeString(); err != nil {
		return
	}
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint32(&s.Type); err != nil {
		return
	}
	return
}

func (SecurityBpf) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeSecurityBpf",
			Section:          "kprobe/security_bpf",
			EbpfFuncName:     "kprobe_security_bpf",
			AttachToFuncName: "security_bpf",
		},
		{
			UID:              "KprobeSysBpf",
			Section:          "kprobe/bpf",
			EbpfFuncName:     "kprobe_sys_bpf",
			AttachToFuncName: "bpf",
		},
	}
}

// func init() {
// 	decoder.RegistEvent(&SecurityBpf{})
// }
