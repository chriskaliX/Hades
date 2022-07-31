package event

import (
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/helper"
	"strconv"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*SocketConnect)(nil)

type SocketConnect struct {
	decoder.BasicEvent `json:"-"`
	Family             int16  `json:"family"`
	Dport              string `json:"dport"`
	Dip                string `json:"dip"`
	Exe                string `json:"-"`
}

func (SocketConnect) ID() uint32 {
	return 1022
}

func (SocketConnect) Name() string {
	return "socket_connect"
}

func (s *SocketConnect) GetExe() string {
	return s.Exe
}

func (s *SocketConnect) DecodeEvent(decoder *decoder.EbpfDecoder) (err error) {
	var (
		index  uint8
		family int16
	)
	// get family firstly
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeInt16(&family); err != nil {
		return
	}
	s.Family = family
	switch s.Family {
	case 2:
		var _port uint16
		if decoder.DecodeUint16BigEndian(&_port); err != nil {
			return
		}
		s.Dport = strconv.FormatUint(uint64(_port), 10)
		var _addr uint32
		if decoder.DecodeUint32BigEndian(&_addr); err != nil {
			return
		}
		s.Dip = helper.PrintUint32IP(_addr)
		decoder.ReadByteSliceFromBuff(8)
	case 10:
		var _port uint16
		if decoder.DecodeUint16BigEndian(&_port); err != nil {
			return
		}
		s.Dport = strconv.FormatUint(uint64(_port), 10)
		var _flowinfo uint32
		if decoder.DecodeUint32BigEndian(&_flowinfo); err != nil {
			return
		}
		var _addr []byte
		_addr, err = decoder.ReadByteSliceFromBuff(16)
		if err != nil {
			return
		}
		s.Dip = helper.Print16BytesSliceIP(_addr)
		// reuse
		if err = decoder.DecodeUint32BigEndian(&_flowinfo); err != nil {
			return
		}
	}
	s.Exe, err = decoder.DecodeString()
	return
}

func (SocketConnect) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			Section:          "kprobe/security_socket_connect",
			EbpfFuncName:     "kprobe_security_socket_connect",
			AttachToFuncName: "security_socket_connect",
		},
	}
}

func init() {
	decoder.RegistEvent(&SocketConnect{})
}
