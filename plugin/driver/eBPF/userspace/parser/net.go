package parser

import (
	"hades-ebpf/userspace/cache"
	"encoding/binary"
	"io"
	"strconv"
)

// test, unfinished
func Net(buf io.Reader, process *cache.Process) (err error) {
	var (
		index  uint8
		family int16
	)
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	err = binary.Read(buf, binary.LittleEndian, &family)
	if err != nil {
		return err
	}
	switch family {
	case 2:
		var port uint16
		if err = binary.Read(buf, binary.BigEndian, &port); err != nil {
			return
		}
		process.RemotePort = strconv.Itoa(int(port))
		var addr uint32
		err = binary.Read(buf, binary.BigEndian, &addr)
		if err != nil {
			return
		}
		process.RemoteAddr = printUint32IP(addr)
		if _, err = readByteSliceFromBuff(buf, 8); err != nil {
			return
		}
		if process.Exe, err = ParseStr(buf); err != nil {
			return
		}
	}
	return
}