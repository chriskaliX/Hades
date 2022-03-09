package parser

import "hades-ebpf/userspace/decoder"

var DefaultPrctl = &Prctl{}

type Prctl struct {
	Exe     string `json:"-"`
	Option  string `json:"option"`
	Newname string `json:"newname,omitempty"`
	Flag    uint32 `json:"flag,omitempty"`
}

func (Prctl) ID() uint32 {
	return 200
}

func (Prctl) String() string {
	return "prctl"
}

func (e *Prctl) GetExe() string {
	return e.Exe
}

func (p *Prctl) Parse() (err error) {
	var index uint8
	var option int32
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt32(&option); err != nil {
		return
	}
	if p.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	switch option {
	case 15:
		p.Option = "PR_SET_NAME"
		if p.Newname, err = decoder.DefaultDecoder.DecodeString(); err != nil {
			return
		}
	case 35:
		p.Option = "PR_SET_MM"
		if err = decoder.DefaultDecoder.DecodeUint32(&p.Flag); err != nil {
			return
		}
	}
	return
}
