package utils

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/mitchellh/hashstructure/v2"
	"go.uber.org/zap"
	"k8s.io/utils/strings/slices"
)

/*
 * The helpers in this file based on libbpfgo.
 *
 * The key of the kernel map is changed into address for this project only.
 * Multikey should be considered. Since we search by both key and name
 *
 * key1 --
 * 			-- map[key]hashcode => map[hashcode]struct
 * key2 --
 */

var Ksyms = NewKernelSymbolsMap()

var whiteList = []string{
	"sys_call_table",
	"idt_table",
	"module_kset",
	"_stext",
	"_etext",
	"vmap_area_list",
}

type KernelSymbolTable struct {
	hashmap     map[interface{}]uint64
	symbolMap   map[uint64]helpers.KernelSymbol
	initialized bool
}

func (k *KernelSymbolTable) set(key interface{}, value helpers.KernelSymbol) error {
	hashcode, err := hashstructure.Hash(key, hashstructure.FormatV2, nil)
	if err != nil {
		return err
	}
	k.hashmap[key] = hashcode
	if _, ok := k.symbolMap[hashcode]; !ok {
		k.symbolMap[hashcode] = value
	}
	return nil
}

func (k *KernelSymbolTable) Get(key interface{}) *helpers.KernelSymbol {
	value, ok := k.hashmap[key]
	if !ok {
		return nil
	}
	if v, ok := k.symbolMap[value]; ok {
		return &v
	}
	return nil
}

// Performance should be improved here
func NewKernelSymbolsMap() *KernelSymbolTable {
	var KernelSymbols = KernelSymbolTable{
		hashmap:   make(map[interface{}]uint64),
		symbolMap: make(map[uint64]helpers.KernelSymbol),
	}

	var arch string
	switch runtime.GOARCH {
	case "386":
		arch = "ia32"
	case "arm64":
		arch = "arm64"
	default:
		arch = "x64"
	}

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		zap.S().Error("could not find /proc/kallsyms")
		return nil
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		//if the line is less than 3 words, we can't parse it (one or more fields missing)
		if len(line) < 3 {
			continue
		}
		symbolAddr, err := strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			continue
		}
		symbolName := line[2]
		symbolType := line[1]
		symbolOwner := "system"
		//if the line is only 3 words then the symbol is owned by the system
		if len(line) > 3 {
			symbolOwner = line[3]
		}
		// special
		lower := strings.ToLower(line[2])

		if slices.Contains(whiteList, lower) || strings.HasPrefix(lower, "entry_int80") {
			symbol := helpers.KernelSymbol{
				Name:    symbolName,
				Type:    symbolType,
				Address: symbolAddr,
				Owner:   symbolOwner,
			}
			KernelSymbols.set(symbolName, symbol)
			KernelSymbols.set(symbolAddr, symbol)
		}
		// do the filter
		if strings.ToLower(line[1]) == "t" || strings.ToLower(line[1]) == "w" {
			// 3 types
			// __x64__sys_open
			// SyS_open
			// __sys_open
			lower = strings.ToLower(line[2])
			if !(strings.HasPrefix(lower, "sys_") || strings.Contains(lower, "__sys_") || strings.HasPrefix(lower, "__"+arch+"_sys_")) {
				continue
			}
			symbol := helpers.KernelSymbol{
				Name:    symbolName,
				Type:    symbolType,
				Address: symbolAddr,
				Owner:   symbolOwner,
			}
			KernelSymbols.set(symbolName, symbol)
			KernelSymbols.set(symbolAddr, symbol)
		}
	}
	KernelSymbols.initialized = true
	return &KernelSymbols
}
