package event

import (
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/helper"

	manager "github.com/ehids/ebpfmanager"
)

type HoneyPot struct {
	Ts       uint64 `json:"timestamp"`
	Len      uint32 `json:"length"`
	Ifindex  uint32 `json:"ifindex"`
	Sip      string `json:"sip"`
	Dip      string `json:"dip"`
	Sport    uint16 `json:"sport"`
	Dport    uint16 `json:"dport"` // dport here is the ingress port
	Protocol uint8  `json:"protocol"`
}

func (HoneyPot) ID() uint32 {
	return 3000
}

func (h *HoneyPot) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	if err = e.DecodeUint64(&h.Ts); err != nil {
		return
	}
	if err = e.DecodeUint32(&h.Len); err != nil {
		return
	}
	if err = e.DecodeUint32(&h.Ifindex); err != nil {
		return
	}
	var _addr []byte = make([]byte, 16)
	// local ip
	if err = e.DecodeBytes(_addr, 16); err != nil {
		return
	}
	h.Sip = helper.Print16BytesSliceIP(_addr)
	// local port
	if err = e.DecodeBytes(_addr, 16); err != nil {
		return
	}
	h.Dip = helper.Print16BytesSliceIP(_addr)
	// remote ip
	if err = e.DecodeUint16BigEndian(&h.Sport); err != nil {
		return
	}
	if err = e.DecodeUint16BigEndian(&h.Dport); err != nil {
		return
	}
	// Align and unused field clean up
	if err = e.DecodeUint8(&h.Protocol); err != nil {
		return
	}
	return
}

func (HoneyPot) Name() string {
	return "honeypot"
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
	}
}

func (HoneyPot) GetMaps() []*manager.Map { return nil }

func (HoneyPot) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

// func init() {
// 	decoder.RegistEvent(&HoneyPot{})
// }
