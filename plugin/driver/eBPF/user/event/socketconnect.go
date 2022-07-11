package event

import (
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/helper"
	"strconv"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultSockConn = &SocketConnect{}

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

func (SocketConnect) String() string {
	return "socket_connect"
}

func (s *SocketConnect) GetExe() string {
	return s.Exe
}

func (s *SocketConnect) Parse() (err error) {
	var (
		index  uint8
		family int16
	)
	// get family firstly
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt16(&family); err != nil {
		return
	}
	s.Family = family
	switch s.Family {
	case 2:
		var _port uint16
		if decoder.DefaultDecoder.DecodeUint16BigEndian(&_port); err != nil {
			return
		}
		s.Dport = strconv.FormatUint(uint64(_port), 10)
		var _addr uint32
		if decoder.DefaultDecoder.DecodeUint32BigEndian(&_addr); err != nil {
			return
		}
		s.Dip = helper.PrintUint32IP(_addr)
		decoder.DefaultDecoder.ReadByteSliceFromBuff(8)
	case 10:
		var _port uint16
		if decoder.DefaultDecoder.DecodeUint16BigEndian(&_port); err != nil {
			return
		}
		s.Dport = strconv.FormatUint(uint64(_port), 10)
		var _flowinfo uint32
		if decoder.DefaultDecoder.DecodeUint32BigEndian(&_flowinfo); err != nil {
			return
		}
		var _addr []byte
		_addr, err = decoder.DefaultDecoder.ReadByteSliceFromBuff(16)
		if err != nil {
			return
		}
		s.Dip = helper.Print16BytesSliceIP(_addr)
		// reuse
		if err = decoder.DefaultDecoder.DecodeUint32BigEndian(&_flowinfo); err != nil {
			return
		}
	}
	s.Exe, err = decoder.DefaultDecoder.DecodeString()
	return
}

func (SocketConnect) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			Section:          "kprobe/security_socket_connect",
			EbpfFuncName:     "kprobe_security_socket_connect",
			AttachToFuncName: "security_socket_connect",
		},
	}
}

func init() {
	decoder.Regist(DefaultSockConn)
}
