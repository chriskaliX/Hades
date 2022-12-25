package event

import (
	"hades-ebpf/user/decoder"
	"strings"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*CallUsermodeHelper)(nil)

type CallUsermodeHelper struct {
	Exe  string `json:"exe"`
	Path string `json:"path"`
	Argv string `json:"argv"`
	Envp string `json:"envp"`
	Wait int32  `json:"wait"`
}

func (CallUsermodeHelper) ID() uint32 {
	return 1030
}

func (c *CallUsermodeHelper) GetExe() string {
	return c.Exe
}

func (CallUsermodeHelper) Name() string {
	return "call_usermodehelper"
}

func (c *CallUsermodeHelper) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	if c.Path, err = e.DecodeString(); err != nil {
		return
	}
	var Argv []string
	var Envp []string
	if Argv, err = e.DecodeStrArray(); err != nil {
		return
	}
	c.Argv = strings.Join(Argv, " ")
	if Envp, err = e.DecodeStrArray(); err != nil {
		return
	}
	c.Envp = strings.Join(Envp, " ")
	var index uint8
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeInt32(&c.Wait); err != nil {
		return
	}
	c.Exe, err = e.DecodeString()
	return
}

func (CallUsermodeHelper) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeCallUsermodehelper",
			Section:          "kprobe/call_usermodehelper",
			EbpfFuncName:     "kprobe_call_usermodehelper",
			AttachToFuncName: "call_usermodehelper",
		},
	}
}

func (CallUsermodeHelper) GetMaps() []*manager.Map { return nil }

func (CallUsermodeHelper) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() {
	decoder.RegistEvent(&CallUsermodeHelper{})
}
