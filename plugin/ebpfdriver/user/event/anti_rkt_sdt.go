package event

import (
	"errors"
	"fmt"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/helper"
	"time"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*SCTScan)(nil)
var kernelSymbols *helper.KernelSymbolTable

// The mapping of syscall index and it's name is not used now
// so the syscall_name is always empty
type SCTScan struct {
	decoder.BasicEvent `json:"-"`
	Index              uint64 `json:"index"`
	SyscallName        string `json:"syscall_name"`
}

func (SCTScan) ID() uint32 {
	return 1200
}

func (s *SCTScan) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	var (
		addr  uint64
		index uint8
	)
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint64(&s.Index); err != nil {
		return
	}
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint64(&addr); err != nil {
		return
	}
	// address is available, not hooked
	if sym := kernelSymbols.Get(addr); sym != nil {
		return ErrIgnore
	}
	return nil
}

func (SCTScan) Name() string {
	return "anti_rkt_sdt_scan"
}

func (s *SCTScan) Trigger(m *manager.Manager) error {
	sct := kernelSymbols.Get("sys_call_table")
	if sct == nil {
		err := errors.New("sys_call_table is not found")
		fmt.Println(err)
		return err
	}

	for i := 0; i < 2000; i++ {
		s.trigger(sct.Address, uint64(i))
	}

	return nil
}

func (s *SCTScan) RegistCron() (decoder.EventCronFunc, *time.Ticker) {
	ticker := time.NewTicker(10 * time.Minute)
	return s.Trigger, ticker
}

//go:noinline
func (s *SCTScan) trigger(sdt_addr uint64, index uint64) error {
	return nil
}

func (SCTScan) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "SCT_Scan",
			Section:          "uprobe/trigger_sct_scan",
			EbpfFuncName:     "trigger_sct_scan",
			AttachToFuncName: "hades-ebpf/user/event.(*SCTScan).trigger",
			BinaryPath:       "/proc/self/exe",
		},
	}
}

func init() {
	decoder.RegistEvent(&SCTScan{})
}
