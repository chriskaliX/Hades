package utils

import (
	"strconv"
)

func ParseUint32(input string) (output uint32) {
	_output, err := strconv.ParseUint(input, 10, 32)
	if err != nil {
		return
	}
	output = uint32(_output)
	return
}

func ParseInt32(input string) (output int32) {
	_output, err := strconv.ParseInt(input, 10, 32)
	if err != nil {
		return
	}
	output = int32(_output)
	return
}
