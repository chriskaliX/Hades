package event

import (
	"edriver/pkg/decoder"

	manager "github.com/gojue/ebpfmanager"
)

var _ decoder.Event = (*CommitCreds)(nil)

type CommitCreds struct {
	Exe            string `json:"-"`
	NewUid         uint32 `json:"newuid"`
	OldUid         uint32 `json:"olduid"`
	PidTree        string `json:"pid_tree"`
	PrivEscalation uint8  `json:"priv_esca"`
}

func (CommitCreds) ID() uint32 {
	return 1011
}

func (CommitCreds) Name() string {
	return "commit_creds"
}

func (c *CommitCreds) GetExe() string {
	return c.Exe
}

func (c *CommitCreds) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	var index uint8
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint32(&c.NewUid); err != nil {
		return
	}
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint32(&c.OldUid); err != nil {
		return
	}
	if c.Exe, err = e.DecodeString(); err != nil {
		return
	}
	if c.PidTree, err = e.DecodePidTree(&c.PrivEscalation); err != nil {
		return
	}
	return
}

func (CommitCreds) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeCommitCreds",
			Section:          "kprobe/commit_creds",
			EbpfFuncName:     "kprobe_commit_creds",
			AttachToFuncName: "commit_creds",
		},
	}
}

func (CommitCreds) GetMaps() []*manager.Map { return nil }

func (CommitCreds) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() {
	decoder.RegistEvent(&CommitCreds{})
}
