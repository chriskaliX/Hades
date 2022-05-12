package event

import (
	"bufio"
	"fmt"
	"hades-ebpf/userspace/decoder"
	"io"
	"os"
	"strconv"
	"strings"
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
	var addr uint32
	var field int32
	var index uint64

	if err = decoder.DefaultDecoder.DecodeUint32(&addr); err != nil {
		return
	}
	fmt.Println(addr)
	if err = decoder.DefaultDecoder.DecodeUint64(&index); err != nil {
		return
	}
	if err = decoder.DefaultDecoder.DecodeInt32(&field); err != nil {
		return
	}
	switch field {
	case 1500:
		a.Field = "syscall"
	case 1501:
		a.Field = "idt"
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

const IDT_CACHE = 0
const SYSCALL_CACHE = 1
const TRIGGER_IDT int = 66
const TRIGGER_SYSCALL int = 65

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
		// Read the kallsyms
		f, err := os.Open("/proc/kallsyms")
		if err != nil {
			zap.S().Error(err)
			return
		}

		updateKMap := func(key string, value string) error {
			v, err := strconv.ParseUint(value, 16, 64)
			if err != nil {
				return err
			}
			k := make([]byte, 64)
			copy(k, "sys_call_table")
			err = ksymbolsMap.Update(unsafe.Pointer(&k[0]), unsafe.Pointer(&v), ebpf.UpdateAny)
			if err != nil {
				return err
			}
			return nil
		}

		buf := bufio.NewReader(f)
		for {
			line, err := buf.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				} else {
					return
				}
			}
			fields := strings.Fields(line)
			if len(fields) != 3 {
				continue
			}
			switch fields[2] {
			case "sys_call_table":
				err = updateKMap("sys_call_table", fields[0])
				if err != nil {
					zap.S().Error(err)
				}
			case "idt_table":
				err = updateKMap("idt_table", fields[0])
				if err != nil {
					zap.S().Error(err)
				}
			}
		}
	})
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
	var syscall_cache int32 = SYSCALL_CACHE
	var value uint64
	for i := 0; i < 300; i++ {
		// update the syscall index we want to scan
		value = uint64(i)
		err := analyzeCache.Update(unsafe.Pointer(&syscall_cache), unsafe.Pointer(&value), ebpf.UpdateAny)
		if err != nil {
			zap.S().Error(err)
			return err
		}
		fmt.Println("triggered: ", i)
		// trigger by the syscall
		syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), uintptr(TRIGGER_SYSCALL), 0)
	}
	return nil
}

// Regist and trigger
func init() {
	decoder.Regist(DefaultAntiRootkit)
}
