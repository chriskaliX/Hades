package event

import (
	"bufio"
	"errors"
	"hades-ebpf/user/decoder"
	"hades-ebpf/utils"
	"io"
	"os"

	manager "github.com/ehids/ebpfmanager"
)

const maxModule = 512

var _ decoder.Event = (*ModuleScan)(nil)

type ModuleScan struct {
	IterCount   uint32 `json:"iter_count"`
	KernelCount uint32 `json:"kernel_count"`
	UserCount   uint32 `json:"user_count"`
}

func (ModuleScan) ID() uint32 {
	return 1203
}

func (ModuleScan) GetExe() string { return "" }

// In DecodeEvent, get the count of /proc/modules, and we do compare them
func (m *ModuleScan) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	m.UserCount = 0
	var index uint8
	var file *os.File
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint32(&m.IterCount); err != nil {
		return
	}
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint32(&m.KernelCount); err != nil {
		return
	}
	if file, err = os.Open("/proc/modules"); err != nil {
		return
	}
	defer file.Close()
	s := bufio.NewScanner(io.LimitReader(file, 1024*1024))
	for s.Scan() {
		m.UserCount += 1
		if m.UserCount >= maxModule {
			break
		}
	}
	if m.UserCount == m.KernelCount {
		err = decoder.ErrIgnore
	}
	return
}

func (ModuleScan) Name() string {
	return "anti_rkt_mod_scan"
}

func (i *ModuleScan) Trigger(m *manager.Manager) error {
	idt := utils.Ksyms.Get("module_kset")
	if idt == nil {
		err := errors.New("mod_kset is not found")
		return err
	}
	// Only trigger the 0x80 here
	i.trigger(idt.Address)
	return nil
}

//go:noinline
func (m *ModuleScan) trigger(mod_kset uint64) error {
	return nil
}

func (m *ModuleScan) RegistCron() (string, decoder.EventCronFunc) {
	return "* */10 * * * *", m.Trigger
}

func (ModuleScan) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "ModuleScan",
			Section:          "uprobe/trigger_module_scan",
			EbpfFuncName:     "trigger_module_scan",
			AttachToFuncName: "hades-ebpf/user/event.(*ModuleScan).trigger",
			BinaryPath:       "/proc/self/exe",
		},
	}
}

func (ModuleScan) GetMaps() []*manager.Map { return nil }

func init() {
	decoder.RegistEvent(&ModuleScan{})
}
