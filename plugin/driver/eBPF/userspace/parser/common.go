package parser

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

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
		buffer := bytepool.Get()
		if err = binary.Read(buf, binary.LittleEndian, buffer.Bytes()[:sz-1]); err != nil {
			buffer.Free()
			return
		}
		strArr = append(strArr, strconv.Itoa(int(pid))+"."+string(buffer.Bytes()[:sz-1]))
		buffer.Free()
		binary.Read(buf, binary.LittleEndian, &dummy)
	}
	return
}

func ParseRemoteAddr(buf io.Reader) (sin_port, sin_addr string, err error) {
	var (
		index  uint8
		family uint16
		port   uint16
		addr   uint32
	)
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	err = binary.Read(buf, binary.LittleEndian, &family)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.BigEndian, &port)
	if err != nil {
		return
	}
	sin_port = strconv.Itoa(int(port))
	err = binary.Read(buf, binary.BigEndian, &addr)
	if err != nil {
		return
	}

	sin_addr = printUint32IP(addr)

	_, err = readByteSliceFromBuff(buf, 8)
	return
}

func readByteSliceFromBuff(buff io.Reader, len int) ([]byte, error) {
	var err error
	res := make([]byte, len)
	err = binary.Read(buff, binary.LittleEndian, &res)
	if err != nil {
		return nil, fmt.Errorf("error reading byte array: %v", err)
	}
	return res, nil
}

func printUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}
