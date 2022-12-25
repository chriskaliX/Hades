package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*KernelReadFile)(nil)

type KernelReadFile struct {
	TypeId   int32  `json:"typeid"`
	Exe      string `json:"-"`
	Filename string `json:"filename"`
	Md5      string `json:"md5"`
}

func (KernelReadFile) ID() uint32 {
	return 1027
}

func (KernelReadFile) Name() string {
	return "kernel_read_file"
}

func (k *KernelReadFile) GetExe() string {
	return k.Exe
}

func (k *KernelReadFile) DecodeEvent(decoder *decoder.EbpfDecoder) (err error) {
	if k.Filename, err = decoder.DecodeString(); err != nil {
		return
	}
	if err = decoder.DecodeInt32(&k.TypeId); err != nil {
		return
	}
	return
}

func (KernelReadFile) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeSecurityKernelReadFile",
			Section:          "kprobe/security_kernel_read_file",
			EbpfFuncName:     "kprobe_security_kernel_read_file",
			AttachToFuncName: "security_kernel_read_file",
		},
	}
}

func (k *KernelReadFile) GetMaps() []*manager.Map { return nil }

func (KernelReadFile) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() {
	decoder.RegistEvent(&KernelReadFile{})
}
