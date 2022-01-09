package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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
		fmt.Println(strconv.Itoa(int(pid)) + "." + string(res))
		strArr = append(strArr, strconv.Itoa(int(pid))+"."+string(res))
		binary.Read(buf, binary.LittleEndian, &dummy)
	}
	return
}

func parseStr(buf io.Reader, test ...int) (str string, err error) {
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
	if len(test) > 0 {
		fmt.Println(str)
	}
	// bufPool.Put(res)
	var dummy int8
	binary.Read(buf, binary.LittleEndian, &dummy)
	return
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
