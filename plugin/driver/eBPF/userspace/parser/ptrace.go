package parser

import (
	"encoding/binary"
	"hades-ebpf/userspace/cache"
	"io"
)

// TODO: unfinished
func Ptrace(buf io.Reader, process *cache.Process) (err error) {
	var (
		index    uint8
		requests int64
		pid      int64
		addr     uint64
	)
	// 0 exe
	if process.Exe, err = ParseStr(buf); err != nil {
		return
	}
	// 1 request
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &requests); err != nil {
		return
	}
	// 2 pid
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &pid); err != nil {
		return
	}
	// 3 addr
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &addr); err != nil {
		return
	}
	// 4 pid tree
	if process.PidTree, err = ParsePidTree(buf); err != nil {
		return
	}
	return
}
