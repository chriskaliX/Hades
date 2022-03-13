package event

import (
	"hades-ebpf/userspace/decoder"
	"strconv"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultSockConn = &SocketConnect{}

var _ decoder.Event = (*SocketConnect)(nil)

type SocketConnect struct {
	Family     int16  `json:"family"`
	RemotePort string `json:"remoteport"`
	RemoteAddr string `json:"remoteaddr"`
	Exe        string `json:"-"`
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
		s.RemotePort = strconv.FormatUint(uint64(_port), 10)
		var _addr uint32
		if decoder.DefaultDecoder.DecodeUint32BigEndian(&_addr); err != nil {
			return
		}
		s.RemoteAddr = printUint32IP(_addr)
		decoder.DefaultDecoder.ReadByteSliceFromBuff(8)
		if s.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
			return
		}
	case 10:
		var _port uint16
		if decoder.DefaultDecoder.DecodeUint16BigEndian(&_port); err != nil {
			return
		}
		s.RemotePort = strconv.FormatUint(uint64(_port), 10)
		var _flowinfo uint32
		if decoder.DefaultDecoder.DecodeUint32BigEndian(&_flowinfo); err != nil {
			return
		}
		var _addr []byte
		_addr, err = decoder.DefaultDecoder.ReadByteSliceFromBuff(16)
		if err != nil {
			return
		}
		s.RemoteAddr = Print16BytesSliceIP(_addr)
		// reuse
		err = decoder.DefaultDecoder.DecodeUint32BigEndian(&_flowinfo)
		if s.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
			return
		}
	}
	return
}

func (SocketConnect) GetProbe() *manager.Probe {
	return &manager.Probe{
		Section:          "kprobe/security_socket_connect",
		EbpfFuncName:     "kprobe_security_socket_connect",
		AttachToFuncName: "security_socket_bind",
	}
}

func init() {
	decoder.Regist(DefaultSockConn)
}
