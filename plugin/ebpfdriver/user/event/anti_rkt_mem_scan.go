package event

import (
	"errors"
	"fmt"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/helper"

	manager "github.com/ehids/ebpfmanager"
)

var _ decoder.Event = (*MemScan)(nil)

// The mapping of syscall index and it's name is not used now
// so the syscall_name is always empty
type MemScan struct {
	decoder.BasicEvent `json:"-"`
	Address            uint64 `json:"address"`
	Count              uint32 `json:"count"`
}

func (MemScan) ID() uint32 {
	return 1207
}

func (s *MemScan) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	var (
		index uint8
	)
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint64(&s.Address); err != nil {
		return
	}
	return nil
}

func (MemScan) Name() string {
	return "anti_rkt_vmap_scan"
}

func (s *MemScan) Trigger(m *manager.Manager) error {
	table := helper.Ksyms.Get("vmap_area_list")
	if table == nil {
		err := errors.New("vmap_area_list is not found")
		fmt.Println(err)
		return err
	}
	fmt.Println("triggered")
	s.trigger(table.Address)
	return nil
}

func (s *MemScan) RegistCron() (string, decoder.EventCronFunc) {
	return "* */30 * * * *", s.Trigger
}

//go:noinline
func (s *MemScan) trigger(list_addr uint64) error {
	return nil
}

func (MemScan) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "MEM_Scan",
			Section:          "uprobe/trigger_memory_scan",
			EbpfFuncName:     "trigger_memory_scan",
			AttachToFuncName: "hades-ebpf/user/event.(*MemScan).trigger",
			BinaryPath:       "/proc/self/exe",
		},
	}
}

// func init() {
// 	decoder.RegistEvent(&MemScan{})
// }
