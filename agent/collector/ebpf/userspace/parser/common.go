package parser

import (
	"encoding/binary"
	"io"
	"strconv"
)

func getStr(buf io.Reader, size uint32) (str string, err error) {
	res := bufPool.get()
	res = make([]byte, size-1)
	defer func() {
		bufPool.put(res)
	}()
	if err = binary.Read(buf, binary.LittleEndian, res); err != nil {
		return
	}
	str = string(res)
	return
}

func ParseStr(buf io.Reader) (str string, err error) {
	var (
		index uint8
		size  uint32
		dummy int8
	)
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &size); err != nil {
		return
	}
	if str, err = getStr(buf, size-1); err != nil {
		return
	}
	binary.Read(buf, binary.LittleEndian, &dummy)
	return
}

func ParseStrArray(buf io.Reader) (strArr []string, err error) {
	var (
		index uint8
		size  uint8
		str   string
		sz    uint32
		dummy uint8
	)
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}

	if err = binary.Read(buf, binary.LittleEndian, &size); err != nil {
		return
	}
	strArr = make([]string, 0)
	for i := 0; i < int(size); i++ {
		if err = binary.Read(buf, binary.LittleEndian, &sz); err != nil {
			break
		}
		if str, err = getStr(buf, sz-1); err != nil {
			return
		}
		strArr = append(strArr, str)
		binary.Read(buf, binary.LittleEndian, &dummy)
	}
	return
}

func ParsePidTree(buf io.Reader) (strArr []string, err error) {
	var (
		index uint8
		size  uint8
		sz    uint32
		pid   uint32
		dummy uint8
	)
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &size); err != nil {
		return
	}
	strArr = make([]string, 0)
	for i := 0; i < int(size); i++ {
		if err = binary.Read(buf, binary.LittleEndian, &pid); err != nil {
			break
		}
		if err = binary.Read(buf, binary.LittleEndian, &sz); err != nil {
			break
		}
		res := bufPool.get()
		res = make([]byte, size-1)
		if err = binary.Read(buf, binary.LittleEndian, res); err != nil {
			bufPool.put(res)
			return
		}
		strArr = append(strArr, strconv.Itoa(int(pid))+"."+string(res))
		bufPool.put(res)
		binary.Read(buf, binary.LittleEndian, &dummy)
	}
	return
}
