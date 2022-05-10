package event

import (
	"hades-ebpf/userspace/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultAntiRootkit = &AntiRootkit{}

var _ decoder.Event = (*AntiRootkit)(nil)

type AntiRootkit struct {
	ModName string `json:"mod_name"`
	Index   int32  `json:"index"`
	Field   string `json:"field"`
}

func (AntiRootkit) ID() uint32 {
	return 1031
}

func (AntiRootkit) String() string {
	return "anti_rootkit"
}

func (a *AntiRootkit) GetExe() string {
	return ""
}

func (a *AntiRootkit) Parse() (err error) {
	if a.ModName, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt32(&a.Index); err != nil {
		return
	}
	var field int32
	if err = decoder.DefaultDecoder.DecodeInt32(&field); err != nil {
		return
	}
	switch field {
	case 1500:
		a.Field = "syscall"
	case 1501:
		a.Field = "idt"
	}
	return
}

func (AntiRootkit) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			Section:          "kprobe/security_file_ioctl",
			EbpfFuncName:     "kprobe_security_file_ioctl",
			AttachToFuncName: "security_file_ioctl",
		},
	}
}

// Regist and trigger
func init() {
	decoder.Regist(DefaultAntiRootkit)
}
