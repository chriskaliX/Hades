package event

import (
	"fmt"
	"hades-ebpf/user/decoder"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"go.uber.org/zap"
)

var _ decoder.Event = (*AntiRootkit)(nil)

// In tracee, uprobes in used to trigger, which is more elegant.
type AntiRootkit struct {
	decoder.BasicEvent `json:"-"`
	Index              uint64 `json:"index"`
	Field              string `json:"field"`
	// Extra field
	Hooked bool `json:"hooked"`
	// Internal field
	status bool `json:"-"`
}

func (AntiRootkit) ID() uint32 {
	return 1031
}

func (AntiRootkit) Name() string {
	return "anti_rootkit"
}

func (a *AntiRootkit) DecodeEvent(e *decoder.EbpfDecoder) (err error) {
	var (
		addr  uint64
		field int32
		index uint8
	)
	// Get address of the syscall/idt funtion
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint64(&addr); err != nil {
		return
	}
	// Get the index id of the syscall/idt function
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeUint64(&a.Index); err != nil {
		return
	}
	// Get the field the this event (syscall or idt)
	if err = e.DecodeUint8(&index); err != nil {
		return
	}
	if err = e.DecodeInt32(&field); err != nil {
		return
	}
	// Fill up the field with values
	switch field {
	case 1500:
		a.Field = "syscall"
	case 1501:
		a.Field = "idt"
	}
	// Get address from the kernel function
	data := kernelSymbols.Get(addr)
	if data == nil {
		a.Hooked = true
		return
	}
	err = ErrIgnore
	return
}

func (AntiRootkit) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "SecurityFileIoctl",
			Section:          "kprobe/security_file_ioctl",
			EbpfFuncName:     "kprobe_security_file_ioctl",
			AttachToFuncName: "security_file_ioctl",
		},
	}
}

func (AntiRootkit) GetMaps() []*manager.Map {
	return []*manager.Map{
		{
			Name: "ksymbols_map",
		},
		{
			Name: "analyze_cache",
		},
	}
}

var once sync.Once

const (
	IDT_CACHE       = 0
	SYSCALL_CACHE   = 1
	TRIGGER_SYSCALL = 65
	TRIGGER_IDT     = 66
	SYSCALLMAX      = 302
	IDTMAX          = 256
)

var (
	syscallCache int32 = SYSCALL_CACHE
	idtCache     int32 = IDT_CACHE
)

func (anti *AntiRootkit) init(m *manager.Manager) {
	once.Do(func() {
		anti.status = false
		// Get ksymbols_map in kernel space
		ksymbolsMap, found, err := m.GetMap("ksymbols_map")
		if err != nil {
			zap.S().Error(err)
			return
		}
		if !found {
			zap.S().Error("ksymbols_map is not found")
			return
		}
		// Wrapper of kernel map function
		updateKMap := func(key string, value uint64) error {
			k := make([]byte, 64)
			copy(k, key)
			err = ksymbolsMap.Update(unsafe.Pointer(&k[0]), unsafe.Pointer(&value), ebpf.UpdateAny)
			if err != nil {
				return err
			}
			return nil
		}
		// update sys_call_table address to map
		sct := kernelSymbols.Get("sys_call_table")
		if sct == nil {
			zap.S().Error("sys_call_table is not found")
			return
		}
		err = updateKMap("sys_call_table", sct.Address)
		if err != nil {
			zap.S().Error(err)
			return
		}
		// update idt_table address to map
		idt := kernelSymbols.Get("idt_table")
		if idt == nil {
			zap.S().Error("idt_table is not found")
			return
		}
		err = updateKMap("idt_table", idt.Address)
		if err != nil {
			zap.S().Error(err)
			return
		}
		anti.status = true
	})
}

// Scan for userspace to work with the kernel part
func (anti *AntiRootkit) Scan(m *manager.Manager) error {
	anti.init(m)
	if !anti.status {
		return fmt.Errorf("kernel scan init error")
	}
	// Add kernel space scan function. TODO: fix up the IDT scan
	if err := anti.scanSCT(m); err != nil {
		zap.S().Error(err)
		return err
	}
	// return anti.scanIDT(m)
	return nil
}

func (anti AntiRootkit) scanSCT(m *manager.Manager) error {
	// update the analyzeCache
	analyzeCache, err := decoder.GetMap(m, "analyze_cache")
	if err != nil {
		return err
	}
	// Update the map_value and trigger
	ptmx, err := os.OpenFile("/proc/self/cmdline", os.O_RDONLY, 0444)
	if err != nil {
		return err
	}
	defer ptmx.Close()
	// Range the syscall to index to
	for index := 0; index <= SYSCALLMAX; index++ {
		// update the syscall index we want to scan
		value := uint64(index)
		if err := analyzeCache.Update(unsafe.Pointer(&syscallCache),
			unsafe.Pointer(&value),
			ebpf.UpdateAny); err != nil {
			return err
		}
		// trigger by the syscall
		syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), uintptr(TRIGGER_SYSCALL), 0)
	}
	return nil
}

func (anti AntiRootkit) scanIDT(m *manager.Manager) error {
	// update the analyzeCache
	analyzeCache, err := decoder.GetMap(m, "analyze_cache")
	if err != nil {
		return err
	}
	// Update the map_value and trigger
	ptmx, err := os.OpenFile("/proc/self/cmdline", os.O_RDONLY, 0444)
	if err != nil {
		return err
	}
	defer ptmx.Close()
	// only 0x80 detected for now
	value := uint64(0x80)
	err = analyzeCache.Update(unsafe.Pointer(&idtCache), unsafe.Pointer(&value), ebpf.UpdateAny)
	if err != nil {
		zap.S().Error(err)
		return err
	}
	// trigger by the syscall
	syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), uintptr(TRIGGER_IDT), 0)
	return nil
}

func (anti *AntiRootkit) RegistCron() (decoder.EventCronFunc, *time.Ticker) {
	ticker := time.NewTicker(30 * time.Second)
	return anti.Scan, ticker
}

// Regist and trigger
// func init() {
// 	var err error
// 	kernelSymbols, err = helper.NewKernelSymbolsMap()
// 	if err != nil {
// 		zap.S().Error(err)
// 		return
// 	}
// 	decoder.RegistEvent(&AntiRootkit{})
// }
