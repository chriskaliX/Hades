package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*SbMount)(nil)

type SbMount struct {
	Exe            string `json:"-"`
	DevName        string `json:"dev_name"`
	Path           string `json:"path"`
	Type           string `json:"type"`
	Flags          uint64 `json:"flags"`
	PidTree        string `json:"pid_tree"`
	PrivEscalation uint8  `json:"priv_esca"`
}

func (SbMount) ID() uint32 {
	return 1029
}

func (SbMount) Name() string {
	return "security_sb_mount"
}

func (s *SbMount) GetExe() string {
	return s.Exe
}

func (s *SbMount) DecodeEvent(decoder *decoder.EbpfDecoder) (err error) {
	var index uint8
	if s.DevName, err = decoder.DecodeString(); err != nil {
		return
	}
	if s.Path, err = decoder.DecodeString(); err != nil {
		return
	}
	if s.Type, err = decoder.DecodeString(); err != nil {
		return
	}
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeUint64(&s.Flags); err != nil {
		return
	}
	if s.Exe, err = decoder.DecodeString(); err != nil {
		return
	}
	if s.PidTree, err = decoder.DecodePidTree(&s.PrivEscalation); err != nil {
		return
	}
	return
}

func (SbMount) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeSecuritySbMount",
			Section:          "kprobe/security_sb_mount",
			EbpfFuncName:     "kprobe_security_sb_mount",
			AttachToFuncName: "security_sb_mount",
		},
	}
}

func (s *SbMount) GetMaps() []*manager.Map { return nil }

func (SbMount) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() {
	decoder.RegistEvent(&SbMount{})
}
