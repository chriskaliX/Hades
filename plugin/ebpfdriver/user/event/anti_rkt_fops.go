package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*FopsCheck)(nil)

type FopsCheck struct {
	decoder.BasicEvent `json:"-"`
	SharedAddr         uint64 `json:"share_addr"`
	Addr               uint64 `json:"addr"`
}

func (FopsCheck) ID() uint32 {
	return 1202
}

/* In tracee, we can get the kernel module name from kallsyms
 * But in hades, for better memory usage, we do not load all the kernel symbols
 */
func (m *FopsCheck) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	var index uint8
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint64(&m.SharedAddr); err != nil {
		return
	}
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint64(&m.Addr); err != nil {
		return
	}
	return nil
}

func (FopsCheck) Name() string {
	return "anti_rkt_fops"
}

func (FopsCheck) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeSecurityFilePermission",
			Section:          "kprobe/security_file_permission",
			EbpfFuncName:     "kprobe_security_file_permission",
			AttachToFuncName: "security_file_permission",
		},
	}
}

func init() {
	decoder.RegistEvent(&FopsCheck{})
}
