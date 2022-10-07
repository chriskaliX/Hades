package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*InodeCreate)(nil)

// Sha256 maybe, and others
type InodeCreate struct {
	decoder.BasicEvent `json:"-"`
	Exe                string `json:"-"`
	Filename           string `json:"filename"`
	Dport              uint16 `json:"dport"`
	Dip                string `json:"dip"`
	Family             uint16 `json:"family"`
}

func (InodeCreate) ID() uint32 {
	return 1028
}

func (InodeCreate) Name() string {
	return "security_inode_create"
}

func (i *InodeCreate) GetExe() string {
	return i.Exe
}

func (i *InodeCreate) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	if i.Exe, err = e.DecodeString(); err != nil {
		return
	}
	if i.Filename, err = e.DecodeString(); err != nil {
		return
	}
	if i.Family, i.Dport, i.Dip, err = e.DecodeRemoteAddr(); err != nil {
		return
	}
	return
}

func (InodeCreate) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeSecurityInodeCreate",
			Section:          "kprobe/security_inode_create",
			EbpfFuncName:     "kprobe_security_inode_create",
			AttachToFuncName: "security_inode_create",
		},
	}
}

func init() {
	decoder.RegistEvent(&InodeCreate{})
}
