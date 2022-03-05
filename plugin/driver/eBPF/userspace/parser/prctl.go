package parser

import (
	"encoding/binary"
	"hades-ebpf/userspace/cache"
	"io"
	"os"
	"strconv"
)

// to be mentioned, all codes here in the userspace, it's just testing.
func Prctl(buf io.Reader, process *cache.Process) (err error) {
	var (
		index uint8
	)
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	os.Stderr.WriteString("index:" + strconv.FormatUint(uint64(index), 10) + "\n")
	if err = binary.Read(buf, binary.LittleEndian, &process.Prctl_Option); err != nil {
		return
	}
	os.Stderr.WriteString("prctl_option:" + strconv.FormatUint(uint64(process.Prctl_Option), 10) + "\n")
	if process.Exe, err = ParseStr(buf); err != nil {
		return
	}
	switch process.Prctl_Option {
	case 15:
		if process.Prctl_Newname, err = ParseStr(buf); err != nil {
			return
		}
	case 35:
		if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
			return
		}
		if err = binary.Read(buf, binary.LittleEndian, &process.Prctl_Flag); err != nil {
			return
		}
	}

	return
}
