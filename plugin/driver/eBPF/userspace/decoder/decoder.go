package decoder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hades-ebpf/userspace/helper"
	"net"
	"strconv"
	"strings"

	"go.uber.org/zap/buffer"
)

// @Reference: https://github.com/aquasecurity/tracee/blob/main/pkg/bufferdecoder/decoder.go
// As binary.Read accept a interface as a parameter, reflection is frequently used
// this package is to try to improve this. Also, based on tracee.
var (
	bytepool buffer.Pool
)

func init() {
	bytepool = buffer.NewPool()
}

type EbpfDecoder struct {
	buffer []byte
	cursor int
}

func New(rawBuffer []byte) *EbpfDecoder {
	return &EbpfDecoder{
		buffer: rawBuffer,
		cursor: 0,
	}
}

// this is for singleton
var DefaultDecoder = &EbpfDecoder{}

func (decoder *EbpfDecoder) SetBuffer(_byte []byte) {
	decoder.buffer = append([]byte(nil), _byte...)
	decoder.cursor = 0
}

func (decoder *EbpfDecoder) BuffLen() int {
	return len(decoder.buffer)
}

func (decoder *EbpfDecoder) ReadAmountBytes() int {
	return decoder.cursor
}

func (decoder *EbpfDecoder) DecodeContext() (c *Context, err error) {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < 168 {
		err = fmt.Errorf("can't read context from buffer: buffer too short")
		return
	}
	ctx := NewContext()
	ctx.Ts = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+8])
	ctx.CgroupID = binary.LittleEndian.Uint64(decoder.buffer[offset+8 : offset+16])
	ctx.UtsInum = binary.LittleEndian.Uint32(decoder.buffer[offset+16 : offset+20])
	ctx.Type = binary.LittleEndian.Uint32(decoder.buffer[offset+20 : offset+24])
	ctx.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+24 : offset+28])
	ctx.Tid = binary.LittleEndian.Uint32(decoder.buffer[offset+28 : offset+32])
	ctx.Uid = binary.LittleEndian.Uint32(decoder.buffer[offset+32 : offset+36])
	ctx.EUid = binary.LittleEndian.Uint32(decoder.buffer[offset+36 : offset+40])
	ctx.Gid = binary.LittleEndian.Uint32(decoder.buffer[offset+40 : offset+44])
	ctx.Ppid = binary.LittleEndian.Uint32(decoder.buffer[offset+44 : offset+48])
	ctx.Sessionid = binary.LittleEndian.Uint32(decoder.buffer[offset+48 : offset+52])
	ctx.Comm = helper.ZeroCopyString(bytes.Trim(decoder.buffer[offset+52:offset+68], "\x00"))
	ctx.PComm = helper.ZeroCopyString(bytes.Trim(decoder.buffer[offset+68:offset+84], "\x00"))
	ctx.Nodename = helper.ZeroCopyString(bytes.Trim(decoder.buffer[offset+84:offset+148], "\x00"))
	ctx.RetVal = uint64(binary.LittleEndian.Uint64(decoder.buffer[offset+148 : offset+156]))
	ctx.Argnum = uint8(binary.LittleEndian.Uint16(decoder.buffer[offset+156 : offset+168]))
	decoder.cursor += int(ctx.GetSizeBytes())
	c = ctx
	return
}

func (decoder *EbpfDecoder) DecodeUint8(msg *uint8) error {
	readAmount := 1
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return fmt.Errorf("can't read context from buffer: buffer too short")
	}
	*msg = decoder.buffer[decoder.cursor]
	decoder.cursor += readAmount
	return nil
}

func (decoder *EbpfDecoder) DecodeInt16(msg *int16) error {
	readAmount := 2
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return fmt.Errorf("can't read context from buffer: buffer too short")
	}
	*msg = int16(binary.LittleEndian.Uint16(decoder.buffer[offset : offset+readAmount]))
	decoder.cursor += readAmount
	return nil
}

func (decoder *EbpfDecoder) DecodeUint16(msg *uint16) error {
	readAmount := 2
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return fmt.Errorf("can't read context from buffer: buffer too short")
	}
	*msg = binary.LittleEndian.Uint16(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

func (decoder *EbpfDecoder) DecodeUint16BigEndian(msg *uint16) error {
	readAmount := 2
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return fmt.Errorf("can't read context from buffer: buffer too short")
	}
	*msg = binary.BigEndian.Uint16(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

func (decoder *EbpfDecoder) DecodeInt32(msg *int32) error {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return fmt.Errorf("can't read context from buffer: buffer too short")
	}
	*msg = int32(binary.LittleEndian.Uint32(decoder.buffer[offset : offset+readAmount]))
	decoder.cursor += readAmount
	return nil
}

func (decoder *EbpfDecoder) DecodeUint32(msg *uint32) error {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return fmt.Errorf("can't read context from buffer: buffer too short")
	}
	*msg = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

func (decoder *EbpfDecoder) DecodeUint32BigEndian(msg *uint32) error {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return fmt.Errorf("can't read context from buffer: buffer too short")
	}
	*msg = binary.BigEndian.Uint32(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

func (decoder *EbpfDecoder) DecodeInt64(msg *int64) error {
	readAmount := 8
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return fmt.Errorf("can't read context from buffer: buffer too short")
	}
	*msg = int64(binary.LittleEndian.Uint64(decoder.buffer[decoder.cursor : decoder.cursor+readAmount]))
	decoder.cursor += readAmount
	return nil
}

func (decoder *EbpfDecoder) DecodeUint64(msg *uint64) error {
	readAmount := 8
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return fmt.Errorf("can't read context from buffer: buffer too short")
	}
	*msg = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

func (decoder *EbpfDecoder) DecodeBytes(msg []byte, size uint32) error {
	offset := decoder.cursor
	castedSize := int(size)
	if len(decoder.buffer[offset:]) < castedSize {
		return fmt.Errorf("can't read context from buffer: buffer too short")
	}
	_ = copy(msg[:], decoder.buffer[offset:offset+castedSize])
	decoder.cursor += castedSize
	return nil
}

func (decoder *EbpfDecoder) DecodeStr(size uint32) (str string, err error) {
	buffer := bytepool.Get()
	defer buffer.Free()
	if err = decoder.DecodeBytes(buffer.Bytes()[:size], size); err != nil {
		return
	}
	str = string(buffer.Bytes()[:size])
	return
}

// get string
func (decoder *EbpfDecoder) DecodeString() (s string, err error) {
	var index uint8
	var size uint32
	var dummy uint8
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeUint32(&size); err != nil {
		return
	}
	// precheck size
	if size >= 8192 {
		err = errors.New(fmt.Sprintf("string size too long, size: %d", size))
		return
	}
	// bytes pool here, TODO
	buf := make([]byte, size-1)
	if err = decoder.DecodeBytes(buf, size-1); err != nil {
		return
	}
	decoder.DecodeUint8(&dummy)
	s = string(buf[:]) // zerocopy
	return
}

func (decoder *EbpfDecoder) DecodeRemoteAddr() (port, addr string, err error) {
	var (
		index  uint8
		family uint16
		_port  uint16
		_addr  uint32
	)
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeUint16(&family); err != nil {
		return
	}
	switch family {
	case 0, 2:
		if err = decoder.DecodeUint16BigEndian(&_port); err != nil {
			return
		}
		if err = decoder.DecodeUint32BigEndian(&_addr); err != nil {
			return
		}
		port = strconv.FormatUint(uint64(_port), 10)
		addr = printUint32IP(_addr)
		_, err = decoder.ReadByteSliceFromBuff(8)
	case 10:
		if decoder.DecodeUint16BigEndian(&_port); err != nil {
			return
		}
		port = strconv.FormatUint(uint64(_port), 10)
		var _flowinfo uint32
		if decoder.DecodeUint32BigEndian(&_flowinfo); err != nil {
			return
		}
		var _addrtmp []byte
		_addrtmp, err = decoder.ReadByteSliceFromBuff(16)
		if err != nil {
			return
		}
		addr = Print16BytesSliceIP(_addrtmp)
		// reuse
		if err = decoder.DecodeUint32BigEndian(&_flowinfo); err != nil {
			return
		}
	}
	return
}

func (decoder *EbpfDecoder) DecodePidTree() (s string, err error) {
	var (
		index uint8
		size  uint8
		sz    uint32
		pid   uint32
		dummy uint8
	)
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeUint8(&size); err != nil {
		return
	}
	strArr := make([]string, 0, 8)
	for i := 0; i < int(size); i++ {
		if err = decoder.DecodeUint32(&pid); err != nil {
			break
		}
		if err = decoder.DecodeUint32(&sz); err != nil {
			break
		}
		buffer := bytepool.Get()
		if err = decoder.DecodeBytes(buffer.Bytes()[:sz-1], sz-1); err != nil {
			buffer.Free()
			return
		}
		strArr = append(strArr, strconv.FormatUint(uint64(pid), 10)+"."+string(buffer.Bytes()[:sz-1]))
		buffer.Free()
		decoder.DecodeUint8(&dummy)
	}
	s = strings.Join(strArr, "<")
	return
}

func (decoder *EbpfDecoder) DecodeStrArray() (strArr []string, err error) {
	var (
		index uint8
		size  uint8
		str   string
		sz    uint32
		dummy uint8
	)
	if err = decoder.DecodeUint8(&index); err != nil {
		return
	}
	if err = decoder.DecodeUint8(&size); err != nil {
		return
	}
	strArr = make([]string, 0, 2)
	for i := 0; i < int(size); i++ {
		if err = decoder.DecodeUint32(&sz); err != nil {
			break
		}
		if str, err = decoder.DecodeStr(sz - 1); err != nil {
			return
		}
		strArr = append(strArr, str)
		decoder.DecodeUint8(&dummy)
	}
	return
}

func (decoder *EbpfDecoder) ReadByteSliceFromBuff(len int) ([]byte, error) {
	var err error
	res := make([]byte, len)
	err = decoder.DecodeBytes(res[:], uint32(len))
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

func Print16BytesSliceIP(in []byte) string {
	ip := net.IP(in)
	return ip.String()
}
