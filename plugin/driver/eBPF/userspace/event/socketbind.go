package event

import (
	"hades-ebpf/userspace/decoder"
	"strconv"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultSockBind = &SocketBind{}

type SocketBind struct {
	Family    int16  `json:"family"`
	LocalPort string `json:"localport"`
	LocalAddr string `json:"localaddr"`
	Exe       string `json:"-"`
}

func (SocketBind) ID() uint32 {
	return 1024
}

func (SocketBind) String() string {
	return "socket_bind"
}

func (s *SocketBind) GetExe() string {
	return s.Exe
}

func (s *SocketBind) Parse() (err error) {
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
		s.LocalPort = strconv.FormatUint(uint64(_port), 10)
		var _addr uint32
		if decoder.DefaultDecoder.DecodeUint32BigEndian(&_addr); err != nil {
			return
		}
		s.LocalAddr = printUint32IP(_addr)
		decoder.DefaultDecoder.ReadByteSliceFromBuff(8)
		if s.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
			return
		}
	}
	return
}

func (SocketBind) GetProbe() *manager.Probe {
	return &manager.Probe{
		Section:          "kprobe/security_socket_bind",
		EbpfFuncName:     "kprobe_security_socket_bind",
		AttachToFuncName: "security_socket_bind",
	}
}

func init() {
	decoder.Regist(DefaultSockBind)
}
