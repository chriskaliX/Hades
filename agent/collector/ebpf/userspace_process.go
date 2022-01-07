package ebpf

import (
	"bytes"
	"encoding/binary"
	"io"
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
