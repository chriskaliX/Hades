package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*InodeRename)(nil)

// Sha256 maybe, and others
type InodeRename struct {
	decoder.BasicEvent `json:"-"`
	Exe                string `json:"-"`
	Old                string `json:"old"`
	New                string `json:"new"`
}

func (InodeRename) ID() uint32 {
	return 1032
}

func (InodeRename) Name() string {
	return "security_inode_rename"
}

func (i *InodeRename) GetExe() string {
	return i.Exe
}

func (i *InodeRename) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	if i.Old, err = e.DecodeString(); err != nil {
		return
	}
	if i.New, err = e.DecodeString(); err != nil {
		return
	}
	return
}

func (InodeRename) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeSecurityInodeRename",
			Section:          "kprobe/security_inode_rename",
			EbpfFuncName:     "kprobe_security_inode_rename",
			AttachToFuncName: "security_inode_rename",
		},
	}
}

func init() {
	decoder.RegistEvent(&InodeRename{})
}
