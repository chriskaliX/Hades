package helper

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/mitchellh/hashstructure/v2"
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
func NewKernelSymbolsMap() (*KernelSymbolTable, error) {
	var KernelSymbols = KernelSymbolTable{
		hashmap:   make(map[interface{}]uint64),
		symbolMap: make(map[uint64]helpers.KernelSymbol),
	}

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("Could not open /proc/kallsyms")
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
		if strings.ToLower(line[1]) == "t" || strings.ToLower(line[1]) == "w" {
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
	return &KernelSymbols, nil
}
