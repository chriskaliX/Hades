package event

import (
	"edriver/pkg/decoder"

	manager "github.com/gojue/ebpfmanager"
)

var _ decoder.Event = (*InodeRename)(nil)

// Sha256 maybe, and others
type InodeRename struct {
	Exe string `json:"-"`
	Old string `json:"old"`
	New string `json:"new"`
}

func (InodeRename) ID() uint32 {
	return 1031
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

func (i *InodeRename) GetMaps() []*manager.Map { return nil }

func (InodeRename) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() {
	decoder.RegistEvent(&InodeRename{})
}
