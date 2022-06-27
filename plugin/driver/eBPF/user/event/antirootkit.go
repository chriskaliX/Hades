package event

import (
	"fmt"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/helper"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"go.uber.org/zap"
)

var DefaultAntiRootkit = &AntiRootkit{}

var _ decoder.Event = (*AntiRootkit)(nil)

type AntiRootkit struct {
	decoder.BasicEvent `json:"-"`
	Index              uint64 `json:"index"`
	Field              string `json:"field"`
}

func (AntiRootkit) ID() uint32 {
	return 1031
}

func (AntiRootkit) String() string {
	return "anti_rootkit"
}

func (a *AntiRootkit) Parse() (err error) {
	var (
		addr  uint64
		field int32
		index uint8
	)
	// get addr
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint64(&addr); err != nil {
		return
	}
	// get index
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint64(&a.Index); err != nil {
		return
	}
	// get field
	if err = decoder.DefaultDecoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt32(&field); err != nil {
		return
	}

	// select field
	switch field {
	case 1500:
		a.Field = "syscall"
	case 1501:
		a.Field = "idt"
	}

	data := kernelSymbols.Get(addr)
	if data == nil {
		// TEST CODE
		fmt.Printf("\033[1;31;40m%s %d is hooked\033[0m. Address: %d\n", a.Field, a.Index, addr)
		return
	}
	err = ErrIgnore
	return
}

func (AntiRootkit) GetProbe() []*manager.Probe {
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
var kernelSymbols *helper.KernelSymbolTable

const (
	IDT_CACHE     = 0
	SYSCALL_CACHE = 1

	TRIGGER_SYSCALL = 65
	TRIGGER_IDT     = 66

	SYSCALLMAX = 302
	IDTMAX     = 256
)

var (
	syscallCache int32 = SYSCALL_CACHE
	idtCache     int32 = IDT_CACHE
)

// Scan for userspace to work with the kernel part
func (anti AntiRootkit) Scan(m *manager.Manager) error {
	// Load to ksymbols_map for the very first-time
	once.Do(func() {
		// Get ksymbols_map in kernel space
		ksymbolsMap, found, err := m.GetMap("ksymbols_map")
		if err != nil {
			zap.S().Error(err)
			return
		}
		if !found {
			err = fmt.Errorf("ksymbols_map not found")
			zap.S().Error(err)
			return
		}
		// update function
		updateKMap := func(key string, value uint64) error {
			if err != nil {
				return err
			}
			k := make([]byte, 64)
			copy(k, key)
			v := value
			err = ksymbolsMap.Update(unsafe.Pointer(&k[0]), unsafe.Pointer(&v), ebpf.UpdateAny)
			if err != nil {
				return err
			}
			return nil
		}
		// update sys_call_table address to map
		if sct := kernelSymbols.Get("sys_call_table"); sct != nil {
			err = updateKMap("sys_call_table", sct.Address)
			if err != nil {
				zap.S().Error(err)
			}
		} else {
			zap.S().Error("sys_call_table is not found")
		}
		// update idt_table address to map
		if idt := kernelSymbols.Get("idt_table"); idt != nil {
			err = updateKMap("idt_table", idt.Address)
			if err != nil {
				zap.S().Error(err)
			}
		} else {
			zap.S().Error("idt_table is not found")
		}
	})
	if err := anti.scanSCT(m); err != nil {
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
	// syscall scan
	for i := 0; i <= SYSCALLMAX; i++ {
		// update the syscall index we want to scan
		value := uint64(i)
		err := analyzeCache.Update(unsafe.Pointer(&syscallCache), unsafe.Pointer(&value), ebpf.UpdateAny)
		if err != nil {
			zap.S().Error(err)
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

/*
 * A wrap of GetMap function.
 * Todo: Move to basic
 */

// Regist and trigger
func init() {
	var err error
	kernelSymbols, err = helper.NewKernelSymbolsMap()
	if err != nil {
		zap.S().Error(err)
		return
	}
	decoder.Regist(DefaultAntiRootkit)
}
