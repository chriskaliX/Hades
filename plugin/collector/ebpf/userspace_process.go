package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

const MAX_STRING_LEN = 256

var bufPool *sync.Pool
var strArrPool *sync.Pool

func parseStrArray(buf io.Reader) (strArr []string, err error) {
	var index uint8
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	var size uint8
	if err = binary.Read(buf, binary.LittleEndian, &size); err != nil {
		return
	}
	// strArr = strArrPool.Get().([]string)
	strArr = make([]string, 0)
	// defer func() {
	// 	strArrPool.Put(strArr)
	// }()
	var sz uint32
	// for useful field
	var dummy uint8
	for i := 0; i < int(size); i++ {
		if err = binary.Read(buf, binary.LittleEndian, &sz); err != nil {
			break
		}
		// res := bufPool.Get().(*bytes.Buffer)
		res := make([]byte, sz-1)
		if err = binary.Read(buf, binary.LittleEndian, res); err != nil {
			// bufPool.Put(res)
			break
		}
		strArr = append(strArr, string(res))
		binary.Read(buf, binary.LittleEndian, &dummy)
		// bufPool.Put(res)
	}
	return
}

func parsePidTree(buf io.Reader) (strArr []string, err error) {
	var index uint8
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	var size uint8
	if err = binary.Read(buf, binary.LittleEndian, &size); err != nil {
		return
	}
	strArr = make([]string, 0)
	var sz uint32
	var pid uint32
	var dummy uint8
	for i := 0; i < int(size); i++ {
		if err = binary.Read(buf, binary.LittleEndian, &pid); err != nil {
			break
		}
		if err = binary.Read(buf, binary.LittleEndian, &sz); err != nil {
			break
		}
		res := make([]byte, sz-1)
		if err = binary.Read(buf, binary.LittleEndian, res); err != nil {
			break
		}
		strArr = append(strArr, strconv.Itoa(int(pid))+"."+string(res))
		binary.Read(buf, binary.LittleEndian, &dummy)
	}
	return
}

func parseStr(buf io.Reader) (str string, err error) {
	var index uint8
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	var strsize uint32
	if err = binary.Read(buf, binary.LittleEndian, &strsize); err != nil {
		return
	}
	// res := bufPool.Get().(*bytes.Buffer)
	res := make([]byte, strsize-1)
	if err = binary.Read(buf, binary.LittleEndian, res); err != nil {
		// bufPool.Put(res)
		return
	}
	str = string(res)
	// bufPool.Put(res)
	var dummy int8
	binary.Read(buf, binary.LittleEndian, &dummy)
	return
}

func parseRemoteAddr(buf io.Reader) (sin_port, sin_addr string, err error) {
	var index uint8
	if err = binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return
	}
	// fmt.Println(index)
	var family uint16
	err = binary.Read(buf, binary.LittleEndian, &family)
	if err != nil {
		return
	}
	// fmt.Println(family)
	var port uint16
	err = binary.Read(buf, binary.BigEndian, &port)
	if err != nil {
		return
	}

	sin_port = strconv.Itoa(int(port))

	var addr uint32
	err = binary.Read(buf, binary.BigEndian, &addr)
	if err != nil {
		return
	}

	sin_addr = PrintUint32IP(addr)

	_, err = readByteSliceFromBuff(buf, 8)
	return
}

/* from tracee, run firstly */
func readByteSliceFromBuff(buff io.Reader, len int) ([]byte, error) {
	var err error
	res := make([]byte, len)
	err = binary.Read(buff, binary.LittleEndian, &res)
	if err != nil {
		return nil, fmt.Errorf("error reading byte array: %v", err)
	}
	return res, nil
}

func PrintUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

func init() {
	bufPool = &sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
	strArrPool = &sync.Pool{
		New: func() interface{} {
			str := make([]string, 0)
			return str
		},
	}
}
