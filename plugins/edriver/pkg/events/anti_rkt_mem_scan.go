package event

import (
	"edriver/pkg/decoder"
	"edriver/utils"
	"errors"

	manager "github.com/gojue/ebpfmanager"
)

var _ decoder.Event = (*MemScan)(nil)

// The mapping of syscall index and it's name is not used now
// so the syscall_name is always empty
type MemScan struct {
	Address uint64 `json:"address"`
	Count   uint32 `json:"count"`
}

func (MemScan) ID() uint32 {
	return 1207
}

func (MemScan) GetExe() string { return "" }

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
	table := utils.Ksyms.Get("vmap_area_list")
	if table == nil {
		err := errors.New("vmap_area_list is not found")
		return err
	}
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
			AttachToFuncName: "edriver/pkg/events.(*MemScan).trigger",
			BinaryPath:       "/proc/self/exe",
		},
	}
}

func (MemScan) GetMaps() []*manager.Map { return nil }

// func init() {
// 	decoder.RegistEvent(&MemScan{})
// }
