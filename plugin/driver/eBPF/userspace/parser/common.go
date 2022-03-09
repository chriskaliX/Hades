package parser

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"

	"go.uber.org/zap/buffer"
)

var (
	bytepool buffer.Pool
)

func init() {
	bytepool = buffer.NewPool()
}

func getStr(buf io.Reader, size uint32) (str string, err error) {
	buffer := bytepool.Get()
	defer buffer.Free()
	if err = binary.Read(buf, binary.LittleEndian, buffer.Bytes()[:size]); err != nil {
		return
	}
	str = string(buffer.Bytes()[:size])
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

func ParsePidTree(buf io.Reader) (pidtree string, err error) {
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
	strArr := make([]string, 0, 8)
	for i := 0; i < int(size); i++ {
		if err = binary.Read(buf, binary.LittleEndian, &pid); err != nil {
			break
		}
		if err = binary.Read(buf, binary.LittleEndian, &sz); err != nil {
			break
		}
		buffer := bytepool.Get()
		if err = binary.Read(buf, binary.LittleEndian, buffer.Bytes()[:sz-1]); err != nil {
			buffer.Free()
			return
		}
		strArr = append(strArr, strconv.FormatUint(uint64(pid), 10)+"."+string(buffer.Bytes()[:sz-1]))
		buffer.Free()
		binary.Read(buf, binary.LittleEndian, &dummy)
	}
	pidtree = strings.Join(strArr, "<")
	return
}

func printUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}
