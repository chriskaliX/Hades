package event

import (
	"fmt"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/helper"
	"strconv"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*SysConnect)(nil)

type SysConnect struct {
	decoder.BasicEvent `json:"-"`
	Family             uint16 `json:"family"`
	Dport              string `json:"dport"`
	Dip                string `json:"dip"`
	Sport              string `json:"sport"`
	Sip                string `json:"sip"`
	Exe                string `json:"-"`
}

func (SysConnect) ID() uint32 {
	return 1022
}

func (SysConnect) Name() string {
	return "sys_connect"
}

func (s *SysConnect) GetExe() string {
	return s.Exe
}

func (s *SysConnect) DecodeEvent(decoder *decoder.EbpfDecoder) (err error) {
	var index uint8
	// get family firstly
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeUint16(&s.Family); err != nil {
		return
	}
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	switch s.Family {
	case 2:
		// Pay attention to memory align
		var _port uint16
		var _addr uint32
		if err = decoder.DecodeUint32BigEndian(&_addr); err != nil {
			return
		}
		s.Sip = helper.PrintUint32IP(_addr)
		if err = decoder.DecodeUint16BigEndian(&_port); err != nil {
			return
		}
		s.Sport = strconv.FormatUint(uint64(_port), 10)
		decoder.ReadByteSliceFromBuff(2)
		if err = decoder.DecodeUint32BigEndian(&_addr); err != nil {
			return
		}
		s.Dip = helper.PrintUint32IP(_addr)
		if err = decoder.DecodeUint16BigEndian(&_port); err != nil {
			return
		}
		s.Dport = strconv.FormatUint(uint64(_port), 10)
		decoder.ReadByteSliceFromBuff(2)
	case 10:
		// struct in6_addr {
		// 	union {
		// 		__u8 u6_addr8[16];
		// 		__be16 u6_addr16[8];
		// 		__be32 u6_addr32[4];
		// 	} in6_u;
		// };
		// typedef struct network_connection_v6 {
		// 	struct in6_addr local_address;
		// 	__u16 local_port;
		// 	struct in6_addr remote_address;
		// 	__u16 remote_port;
		// 	__u32 flowinfo;
		// 	__u32 scope_id;
		// } net_conn_v6_t;
		var _port uint16
		var _addr []byte = make([]byte, 16)
		// local ip
		if err = decoder.DecodeBytes(_addr, 16); err != nil {
			return
		}
		s.Sip = helper.Print16BytesSliceIP(_addr)
		// local port
		if err = decoder.DecodeUint16BigEndian(&_port); err != nil {
			return
		}
		s.Sport = strconv.FormatUint(uint64(_port), 10)
		decoder.ReadByteSliceFromBuff(2)
		// remote ip
		if err = decoder.DecodeBytes(_addr, 16); err != nil {
			return
		}
		s.Dip = helper.Print16BytesSliceIP(_addr)
		// remote port
		if err = decoder.DecodeUint16BigEndian(&_port); err != nil {
			return
		}
		s.Dport = strconv.FormatUint(uint64(_port), 10)
		// Align and unused field clean up
		decoder.ReadByteSliceFromBuff(10)
	default:
		err = fmt.Errorf("family %d not support", s.Family)
		return
	}
	s.Exe, err = decoder.DecodeString()
	return
}

func (SysConnect) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeTcpConnect",
			Section:          "kprobe/tcp_connect",
			EbpfFuncName:     "kprobe_tcp_connect",
			AttachToFuncName: "tcp_connect",
		},
		{
			UID:              "KretprobeTcpConnect",
			Section:          "kretprobe/connect",
			EbpfFuncName:     "kretprobe_tcp_connect",
			AttachToFuncName: "connect",
		},
	}
}

func init() {
	decoder.RegistEvent(&SysConnect{})
}
