package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultCommitCreds = &CommitCreds{}

var _ decoder.Event = (*CommitCreds)(nil)

type CommitCreds struct {
	decoder.BasicEvent `json:"-"`
	Exe                string `json:"-"`
	NewUid             uint32 `json:"newuid"`
	OldUid             uint32 `json:"olduid"`
	PidTree            string `json:"pid_tree"`
	PrivEscalation     uint8  `json:"priv_esca"`
}

func (CommitCreds) ID() uint32 {
	return 1011
}

func (CommitCreds) String() string {
	return "commit_creds"
}

func (c *CommitCreds) GetExe() string {
	return c.Exe
}

func (c *CommitCreds) Parse() (err error) {
	var index uint8
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint32(&c.NewUid); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint32(&c.OldUid); err != nil {
		return
	}
	if c.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if c.PidTree, err = decoder.DefaultDecoder.DecodePidTree(&c.PrivEscalation); err != nil {
		return
	}
	return
}

func (CommitCreds) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeCommitCreds",
			Section:          "kprobe/commit_creds",
			EbpfFuncName:     "kprobe_commit_creds",
			AttachToFuncName: "commit_creds",
		},
	}
}

func init() {
	decoder.Regist(DefaultCommitCreds)
}
