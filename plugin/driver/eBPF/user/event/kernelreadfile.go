package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultKernelReadFile = &KernelReadFile{}

var _ decoder.Event = (*KernelReadFile)(nil)

type KernelReadFile struct {
	decoder.BasicEvent `json:"-"`
	TypeId             int32  `json:"typeid"`
	Exe                string `json:"-"`
	Filename           string `json:"filename"`
	Md5                string `json:"md5"`
}

func (KernelReadFile) ID() uint32 {
	return 1027
}

func (KernelReadFile) String() string {
	return "kernel_read_file"
}

func (k *KernelReadFile) GetExe() string {
	return k.Exe
}

func (k *KernelReadFile) Parse() (err error) {
	if k.Filename, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt32(&k.TypeId); err != nil {
		return
	}
	return
}

func (KernelReadFile) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeSecurityKernelReadFile",
			Section:          "kprobe/security_kernel_read_file",
			EbpfFuncName:     "kprobe_security_kernel_read_file",
			AttachToFuncName: "security_kernel_read_file",
		},
	}
}

func init() {
	decoder.Regist(DefaultKernelReadFile)
}
