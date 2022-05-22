package event

import (
	"hades-ebpf/userspace/decoder"
	"strings"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultCallUsermodeHelper = &CallUsermodeHelper{}

var _ decoder.Event = (*CallUsermodeHelper)(nil)

type CallUsermodeHelper struct {
	decoder.BasicEvent `json:"-"`
	Exe                string `json:"-"`
	Path               string `json:"path"`
	Argv               string `json:"argv"`
	Envp               string `json:"envp"`
	Wait               int32  `json:"wait"`
}

func (CallUsermodeHelper) ID() uint32 {
	return 1030
}

func (CallUsermodeHelper) String() string {
	return "call_usermodehelper"
}

func (c *CallUsermodeHelper) GetExe() string {
	return c.Exe
}

func (c *CallUsermodeHelper) Parse() (err error) {
	if c.Path, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	var Argv []string
	var Envp []string
	if Argv, err = decoder.DefaultDecoder.DecodeStrArray(); err != nil {
		return
	}
	c.Argv = strings.Join(Argv, " ")
	if Envp, err = decoder.DefaultDecoder.DecodeStrArray(); err != nil {
		return
	}
	c.Envp = strings.Join(Envp, " ")
	if err = decoder.DefaultDecoder.DecodeInt32(&c.Wait); err != nil {
		return
	}
	c.Exe, err = decoder.DefaultDecoder.DecodeString()
	return
}

func (CallUsermodeHelper) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeCallUsermodehelper",
			Section:          "kprobe/call_usermodehelper",
			EbpfFuncName:     "kprobe_call_usermodehelper",
			AttachToFuncName: "call_usermodehelper",
		},
	}
}

func init() {
	decoder.Regist(DefaultCallUsermodeHelper)
}
