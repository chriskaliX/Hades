package event

import (
	"hades-ebpf/userspace/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultInodeCreate = &InodeCreate{}

var _ decoder.Event = (*InodeCreate)(nil)

// Sha256 maybe, and others
type InodeCreate struct {
	Exe        string `json:"exe"`
	Filename   string `json:"filename"`
	RemotePort string `json:"remoteport"`
	RemoteAddr string `json:"remoteaddr"`
}

func (InodeCreate) ID() uint32 {
	return 1028
}

func (InodeCreate) String() string {
	return "security_inode_create"
}

func (i *InodeCreate) GetExe() string {
	return i.Exe
}

func (i *InodeCreate) Parse() (err error) {
	if i.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if i.Filename, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if i.RemotePort, i.RemoteAddr, err = decoder.DefaultDecoder.DecodeRemoteAddr(); err != nil {
		return
	}
	return
}

func (InodeCreate) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			Section:          "kprobe/security_inode_create",
			EbpfFuncName:     "kprobe_security_inode_create",
			AttachToFuncName: "security_inode_create",
		},
	}
}

func init() {
	decoder.Regist(DefaultInodeCreate)
}
