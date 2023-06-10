/*portscan detection will be move to eguard, since it's tc related*/
package event

import (
	"hades-ebpf/user/decoder"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*HoneyPot)(nil)

type HoneyPot struct {
	Sip      string `json:"sip"`
	Dip      string `json:"dip"`
	Sport    uint16 `json:"sport"`
	Dport    uint16 `json:"dport"` // dport here is the ingress port
	Family   uint16 `json:"family"`
	Protocol uint8  `json:"protocol"`
}

func (HoneyPot) ID() uint32 {
	return 3000
}

func (h *HoneyPot) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	if h.Family, h.Sport, h.Dport, h.Sip, h.Dip, err = e.DecodeAddr(); err != nil {
		return
	}
	var index uint8
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint8(&h.Protocol); err != nil {
		return
	}
	return
}

func (HoneyPot) Name() string {
	return "honeypot_portscan"
}

func (HoneyPot) GetExe() string {
	return ""
}

func (HoneyPot) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		// {
		// 	Section:          "classifier/ingress",
		// 	EbpfFuncName:     "hades_ingress",
		// 	Ifindex:          0,
		// 	Ifname:           "ens33",
		// 	NetworkDirection: manager.Ingress,
		// },
		// {
		// 	Section:          "classifier/egress",
		// 	EbpfFuncName:     "hades_egress",
		// 	Ifindex:          0,
		// 	Ifname:           "ens33",
		// 	NetworkDirection: manager.Egress,
		// },
		{
			UID:              "kprobe_tcp_reset",
			Section:          "kprobe/tcp_v4_send_reset",
			EbpfFuncName:     "kprobe_tcp_reset",
			AttachToFuncName: "tcp_v4_send_reset",
		},
		{
			UID:              "icmp",
			Section:          "kprobe/__icmp_send",
			EbpfFuncName:     "kprobe_icmp_send",
			AttachToFuncName: "__icmp_send",
		},
		{
			UID:              "icmp6",
			Section:          "kprobe/icmp6_send",
			EbpfFuncName:     "krpobe_icmp6_send",
			AttachToFuncName: "icmp6_send",
		},
		{
			UID:              "krpobe_icmp_rcv",
			Section:          "kprobe/icmp_rcv",
			EbpfFuncName:     "krpobe_icmp_rcv",
			AttachToFuncName: "icmp_rcv",
		},
		{
			UID:              "krpobe_icmpv6_rcv",
			Section:          "kprobe/icmpv6_rcv",
			EbpfFuncName:     "krpobe_icmpv6_rcv",
			AttachToFuncName: "icmpv6_rcv",
		},
	}
}

func (HoneyPot) GetMaps() []*manager.Map { return nil }

func (HoneyPot) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

// func init() {
// 	decoder.RegistEvent(&HoneyPot{})
// }
