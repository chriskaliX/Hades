package event

import (
	"errors"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/helper"
	"time"

	manager "github.com/ehids/ebpfmanager"
	"go.uber.org/zap"
)

type IDTScan struct {
	decoder.BasicEvent `json:"-"`
	Index              uint64 `json:"index"`
}

func (IDTScan) ID() uint32 {
	return 1201
}

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
	if idt := kernelSymbols.Get(addr); idt != nil {
		return ErrIgnore
	}
	return nil
}

func (IDTScan) Name() string {
	return "anti_rkt_idt_scan"
}

func (i *IDTScan) Trigger(m *manager.Manager) error {
	idt := kernelSymbols.Get("idt_table")
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

func (i *IDTScan) RegistCron() (decoder.EventCronFunc, *time.Ticker) {
	ticker := time.NewTicker(10 * time.Minute)
	return i.Trigger, ticker
}

func (IDTScan) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "IDT_Scan",
			Section:          "uprobe/trigger_idt_scan",
			EbpfFuncName:     "trigger_idt_scan",
			AttachToFuncName: "hades-ebpf/user/event.(*IDTScan).trigger",
			BinaryPath:       "/proc/self/exe",
		},
	}
}

func init() {
	var err error
	kernelSymbols, err = helper.NewKernelSymbolsMap()
	if err != nil {
		zap.S().Error(err)
		return
	}
	decoder.RegistEvent(&IDTScan{})
}
