package event

import (
	"hades-ebpf/userspace/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultSbMount = &SbMount{}

var _ decoder.Event = (*SbMount)(nil)

type SbMount struct {
	Exe     string `json:"-"`
	DevName string `json:"dev_name"`
	Path    string `json:"path"`
	Type    string `json:"type"`
	Flags   uint64 `json:"flags"`
	PidTree string `json:"pidtree"`
}

func (SbMount) ID() uint32 {
	return 1029
}

func (SbMount) String() string {
	return "security_sb_mount"
}

func (s *SbMount) GetExe() string {
	return s.Exe
}

func (s *SbMount) Parse() (err error) {
	if s.DevName, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if s.Path, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if s.Type, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint64(&s.Flags); err != nil {
		return
	}
	if s.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if s.PidTree, err = decoder.DefaultDecoder.DecodePidTree(); err != nil {
		return
	}
	return
}

func (SbMount) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			Section:          "kprobe/security_sb_mount",
			EbpfFuncName:     "kprobe_security_sb_mount",
			AttachToFuncName: "security_sb_mount",
		},
	}
}

func init() {
	decoder.Regist(DefaultSbMount)
}
