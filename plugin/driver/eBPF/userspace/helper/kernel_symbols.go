package helper

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/jwangsadinata/go-multimap/setmultimap"
)

/*
 * The helpers in this file based on libbpfgo.
 *
 * The key of the kernel map is changed into address for this project only.
 */

type KernelSymbolTableByAddr struct {
	symbolMap   *setmultimap.MultiMap
	initialized bool
}

func NewKernelSymbolsMapByAddr() (*KernelSymbolTableByAddr, error) {
	var KernelSymbols = KernelSymbolTableByAddr{}
	KernelSymbols.symbolMap = setmultimap.New()
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
		symbol := helpers.KernelSymbol{
			Name:    symbolName,
			Type:    symbolType,
			Address: symbolAddr,
			Owner:   symbolOwner}

		KernelSymbols.symbolMap.Put(symbolAddr, symbol)
		KernelSymbols.symbolMap.Put(symbolName, symbol)
	}
	KernelSymbols.initialized = true
	return &KernelSymbols, nil
}
