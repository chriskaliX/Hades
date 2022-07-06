package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultUdpRecvmsg = &UdpRecvmsg{}

var _ decoder.Event = (*UdpRecvmsg)(nil)

type UdpRecvmsg struct {
	decoder.BasicEvent `json:"-"`
	Exe                string `json:"-"`
	Opcode             int32  `json:"opcode"`
	Rcode              int32  `json:"rcode"`
	Qtype              int32  `json:"qtype"`
	Atype              int32  `json:"atype"`
	DnsData            string `json:"dns_data"`
}

func (UdpRecvmsg) ID() uint32 {
	return 1025
}

func (UdpRecvmsg) String() string {
	return "udp_recvmsg"
}

func (u *UdpRecvmsg) GetExe() string {
	return u.Exe
}

func (u *UdpRecvmsg) Parse() (err error) {
	var index uint8
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt32(&u.Opcode); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt32(&u.Rcode); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt32(&u.Qtype); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt32(&u.Atype); err != nil {
		return
	}
	if u.DnsData, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if u.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	return
}

func (u *UdpRecvmsg) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "KprobeUdpRecvmsg",
			Section:          "kprobe/udp_recvmsg",
			EbpfFuncName:     "kprobe_udp_recvmsg",
			AttachToFuncName: "udp_recvmsg",
		},
		{
			UID:              "KretprobeUdpRecvmsg",
			Section:          "kretprobe/udp_recvmsg",
			EbpfFuncName:     "kretprobe_udp_recvmsg",
			AttachToFuncName: "udp_recvmsg",
		},
	}
}

func init() {
	decoder.Regist(DefaultUdpRecvmsg)
}
