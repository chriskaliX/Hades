package parser

import (
	"collector/cache"
	"encoding/binary"
	"io"
)

// TODO: unfinished
func Ptrace(buf io.Reader, process *cache.Process) (err error) {
	var (
		index    uint8
		requests int32
		pid      int32
		addr     uint32
		data     uint32
	)
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &requests); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &addr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data); err != nil {
		return
	}
	return
}
