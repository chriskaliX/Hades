package parser

import (
	"collector/model"
	"encoding/binary"
	"io"
)

// TODO: unfinished
func Prctl(buf io.Reader, process *model.Process) (err error) {
	var (
		index  uint8
		option int32
		arg2   uint32
	)
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &option); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &arg2); err != nil {
		return
	}
	return
}
