package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*InodeLink)(nil)

// Sha256 maybe, and others
type InodeLink struct {
	Exe string `json:"-"`
	Old string `json:"old"`
	New string `json:"new"`
}

func (InodeLink) ID() uint32 {
	return 1032
}

func (InodeLink) Name() string {
	return "security_inode_link"
}

func (i *InodeLink) GetExe() string {
	return ""
}

func (i *InodeLink) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	if i.Old, err = e.DecodeString(); err != nil {
		return
	}
	if i.New, err = e.DecodeString(); err != nil {
		return
	}
	return
}

func (InodeLink) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeSecurityInodeLink",
			Section:          "kprobe/security_inode_link",
			EbpfFuncName:     "kprobe_security_inode_link",
			AttachToFuncName: "security_inode_link",
		},
	}
}

func (i *InodeLink) GetMaps() []*manager.Map { return nil }

func (InodeLink) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() {
	decoder.RegistEvent(&InodeLink{})
}
