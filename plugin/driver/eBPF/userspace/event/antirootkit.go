package event

import (
	"fmt"
	"hades-ebpf/userspace/decoder"
	"hades-ebpf/userspace/helper"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"go.uber.org/zap"
)

var DefaultAntiRootkit = &AntiRootkit{}

var _ decoder.Event = (*AntiRootkit)(nil)

type AntiRootkit struct {
	decoder.BasicEvent `json:"-"`
	Index              uint32 `json:"index"`
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
		addr   uint64
		field  int32
		index  uint64
		_index uint8
	)
	// get addr
	if err = decoder.DefaultDecoder.DecodeUint8(&_index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint64(&addr); err != nil {
		return
	}
	// get index
	if err = decoder.DefaultDecoder.DecodeUint8(&_index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeUint64(&index); err != nil {
		return
	}
	// get field
	if err = decoder.DefaultDecoder.DecodeUint8(&_index); err != nil {
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
		fmt.Printf("\033[1;31;40m%s %d is hooked\033[0m\n", a.Field, index)
	}

	return
}

func (AntiRootkit) GetProbe() []*manager.Probe {
	return []*manager.Probe{
		{
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
	IDT_CACHE = iota
	SYSCALL_CACHE
)

const (
	TRIGGER_SYSCALL int = iota + 65
	TRIGGER_IDT
)

// Scan for userspace to work with the kernel part
func (AntiRootkit) Scan(m *manager.Manager) error {
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

		sct := kernelSymbols.Get("sys_call_table")

		if sct != nil {
			err = updateKMap("sys_call_table", sct.Address)
			if err != nil {
				zap.S().Error(err)
			}
		}

		idt := kernelSymbols.Get("idt_table")
		if sct != nil {
			err = updateKMap("idt_table", idt.Address)
			if err != nil {
				zap.S().Error(err)
			}
		}
	})
	time.Sleep(5 * time.Second)
	analyzeCache, found, err := m.GetMap("analyze_cache")
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("analyze_cache not found")
	}
	// Update the map_value and trigger, 300 just for test
	ptmx, err := os.OpenFile("test", os.O_RDONLY, 0444)
	if err != nil {
		return err
	}
	defer ptmx.Close()
	var (
		syscall_cache int32 = SYSCALL_CACHE
		value         uint64
	)

	for i := 0; i <= 302; i++ {
		// update the syscall index we want to scan
		value = uint64(i)
		err := analyzeCache.Update(unsafe.Pointer(&syscall_cache), unsafe.Pointer(&value), ebpf.UpdateAny)
		if err != nil {
			zap.S().Error(err)
			return err
		}
		// trigger by the syscall
		syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), uintptr(TRIGGER_SYSCALL), 0)
	}
	return nil
}

var globalSymbolOwner = "system"

// From tracee.
func LoadKallsymsValues(ksymsTable *helpers.KernelSymbolTable, ksymbols []string) map[string]*helpers.KernelSymbol {
	kallsymsMap := make(map[string]*helpers.KernelSymbol)
	for _, name := range ksymbols {
		symbol, err := ksymsTable.GetSymbolByName(globalSymbolOwner, name)
		if err == nil {
			kallsymsMap[name] = symbol
		}
	}
	return kallsymsMap
}

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
