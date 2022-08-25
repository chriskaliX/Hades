package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*DoInitModule)(nil)

type DoInitModule struct {
	decoder.BasicEvent `json:"-"`
	Exe                string `json:"-"`
	Modname            string `json:"modname"`
	Pidtree            string `json:"pidt_ree"`
	Cwd                string `json:"cwd"`
	PrivEscalation     uint8  `json:"priv_esca"`
}

func (DoInitModule) ID() uint32 {
	return 1026
}

func (DoInitModule) Name() string {
	return "do_init_module"
}

func (d *DoInitModule) GetExe() string {
	return d.Exe
}

func (d *DoInitModule) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	if d.Modname, err = e.DecodeString(); err != nil {
		return
	}
	if d.Exe, err = e.DecodeString(); err != nil {
		return
	}
	if d.Pidtree, err = e.DecodePidTree(&d.PrivEscalation); err != nil {
		return
	}
	if d.Cwd, err = e.DecodeString(); err != nil {
		return
	}
	return
}

func (d *DoInitModule) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeDoInitModule",
			Section:          "kprobe/do_init_module",
			EbpfFuncName:     "kprobe_do_init_module",
			AttachToFuncName: "do_init_module",
		},
	}
}

func init() {
	decoder.RegistEvent(&DoInitModule{})
}
