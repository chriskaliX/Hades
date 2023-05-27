package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*UdpRecvmsg)(nil)

type UdpRecvmsg struct {
	Exe     string `json:"-"`
	Opcode  int32  `json:"opcode"`
	Rcode   int32  `json:"rcode"`
	Qtype   int32  `json:"qtype"`
	Atype   int32  `json:"atype"`
	DnsData string `json:"dns_data"`
	Sip     string `json:"sip"`
	Sport   uint16 `json:"sport"`
	Dip     string `json:"dip"`
	Dport   uint16 `json:"dport"`
}

func (UdpRecvmsg) ID() uint32 {
	return 1025
}

func (UdpRecvmsg) Name() string {
	return "udp_recvmsg"
}

func (u *UdpRecvmsg) GetExe() string {
	return u.Exe
}

func (u *UdpRecvmsg) DecodeEvent(decoder *decoder.EbpfDecoder) (err error) {
	var index uint8
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeInt32(&u.Opcode); err != nil {
		return
	}
	if err = decoder.DecodeInt32(&u.Rcode); err != nil {
		return
	}
	if err = decoder.DecodeInt32(&u.Qtype); err != nil {
		return
	}
	if err = decoder.DecodeInt32(&u.Atype); err != nil {
		return
	}
	if u.DnsData, err = decoder.DecodeString(); err != nil {
		return
	}
	if u.Exe, err = decoder.DecodeString(); err != nil {
		return
	}
	if _, u.Sport, u.Dport, u.Sip, u.Dip, err = decoder.DecodeAddr(); err != nil {
		return
	}
	return
}

func (u *UdpRecvmsg) GetProbes() []*manager.Probe {
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

func (u *UdpRecvmsg) GetMaps() []*manager.Map { return nil }

func (UdpRecvmsg) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() {
	decoder.RegistEvent(&UdpRecvmsg{})
}
