package event

import (
	"fmt"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/helper"

	manager "github.com/ehids/ebpfmanager"
)

type HoneyPot struct {
	decoder.BasicEvent `json:"-"`
}

func (HoneyPot) ID() uint32 {
	return 3000
}

func (h *HoneyPot) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	var index uint8
	var _addr uint32
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint32BigEndian(&_addr); err != nil {
		return
	}
	addr := helper.PrintUint32IP(_addr)
	fmt.Println(addr)
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
		{
			Section:       "xdp/ingress",
			EbpfFuncName:  "hades_xdp",
			Ifindex:       0,
			Ifname:        "eth0",
			XDPAttachMode: manager.XdpAttachModeSkb,
		},
	}
}

// func init() {
// 	decoder.RegistEvent(&HoneyPot{})
// }
