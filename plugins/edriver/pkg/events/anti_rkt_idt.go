package event

import (
	"edriver/pkg/decoder"
	"edriver/utils"
	"errors"
	"fmt"

	manager "github.com/gojue/ebpfmanager"
)

var _ decoder.Event = (*IDTScan)(nil)

type IDTScan struct {
	Index   uint64 `json:"index"`
	Address string `json:"addr"`
}

func (IDTScan) ID() uint32 {
	return 1201
}

func (IDTScan) GetExe() string { return "" }

func (i *IDTScan) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	var (
		addr       uint64
		call_index uint64
		index      uint8
	)
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint64(&call_index); err != nil {
		return
	}
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint64(&addr); err != nil {
		return
	}
	if idt := utils.Ksyms.Get(addr); idt != nil {
		return decoder.ErrIgnore
	}
	i.Address = fmt.Sprintf("%x", addr)
	return nil
}

func (IDTScan) Name() string {
	return "anti_rkt_idt_scan"
}

func (i *IDTScan) Trigger(m *manager.Manager) error {
	idt := utils.Ksyms.Get("idt_table")
	if idt == nil {
		err := errors.New("idt_table is not found")
		return err
	}
	// Only trigger the 0x80 here
	i.trigger(idt.Address, uint64(128))
	return nil
}

//go:noinline
func (i *IDTScan) trigger(idt_addr uint64, index uint64) error {
	return nil
}

func (i *IDTScan) RegistCron() (string, decoder.EventCronFunc) {
	return "* */10 * * * *", i.Trigger
}

func (IDTScan) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "IDT_Scan",
			Section:          "uprobe/trigger_idt_scan",
			EbpfFuncName:     "trigger_idt_scan",
			AttachToFuncName: "edriver/pkg/events.(*IDTScan).trigger",
			BinaryPath:       "/proc/self/exe",
		},
	}
}

func (IDTScan) GetMaps() []*manager.Map { return nil }

func init() {
	decoder.RegistEvent(&IDTScan{})
}
