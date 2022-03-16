package event

import (
	"hades-ebpf/userspace/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultDoInitModule = &DoInitModule{}

var _ decoder.Event = (*DoInitModule)(nil)

type DoInitModule struct {
	Exe     string `json:"-"`
	Modname string `json:"modname"`
	Pidtree string `json:"pidtree"`
	Cwd     string `json:"cwd"`
}

func (DoInitModule) ID() uint32 {
	return 1026
}

func (DoInitModule) String() string {
	return "do_init_module"
}

func (d *DoInitModule) GetExe() string {
	return d.Exe
}

func (d *DoInitModule) Parse() (err error) {
	if d.Modname, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if d.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if d.Pidtree, err = decoder.DefaultDecoder.DecodePidTree(); err != nil {
		return
	}
	if d.Cwd, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	return
}

func (d *DoInitModule) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			Section:          "kprobe/do_init_module",
			EbpfFuncName:     "kprobe_do_init_module",
			AttachToFuncName: "do_init_module",
		},
	}
}

func init() {
	decoder.Regist(DefaultDoInitModule)
}
