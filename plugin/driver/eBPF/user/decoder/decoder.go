package decoder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hades-ebpf/user/helper"
	"hades-ebpf/user/share"
	"strconv"
	"strings"
)

var DefaultDecoder = NewEbpfDecoder(make([]byte, 0))

const (
	sizeint8  = 1
	sizeint16 = 2
	sizeint32 = 4
	sizeint64 = 8
)

// dummy field for internal uses
var dummy uint8

// eBPF events decoder, functions in this struct is not thread-safe
type EbpfDecoder struct {
	// raw buffer which is read from kern perf(or ringbuf)
	buffer []byte
	// cursor of the buffer
	cursor int
	// index of the event, for less alloc since it's internal
	index uint8
}

func NewEbpfDecoder(rawBuffer []byte) *EbpfDecoder {
	return &EbpfDecoder{
		buffer: rawBuffer,
		cursor: 0,
	}
}

// ReInit the decoder by accepting a new event buffer
func (decoder *EbpfDecoder) ReInit(_byte []byte) {
	decoder.buffer = append([]byte(nil), _byte...)
	decoder.cursor = 0
	decoder.index = 0
}

func (decoder *EbpfDecoder) BuffLen() int {
	return len(decoder.buffer)
}

func (decoder *EbpfDecoder) ReadAmountBytes() int {
	return decoder.cursor
}

func (decoder *EbpfDecoder) DecodeUint8(msg *uint8) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < sizeint8 {
		return fmt.Errorf("read uint8 failed, offset: %d", offset)
	}
	*msg = decoder.buffer[decoder.cursor]
	decoder.cursor += sizeint8
	return nil
}

func (decoder *EbpfDecoder) DecodeInt16(msg *int16) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < sizeint16 {
		return fmt.Errorf("read int16 failed, offset: %d", offset)
	}
	*msg = int16(binary.LittleEndian.Uint16(decoder.buffer[offset : offset+sizeint16]))
	decoder.cursor += sizeint16
	return nil
}

func (decoder *EbpfDecoder) DecodeUint16(msg *uint16) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < sizeint16 {
		return fmt.Errorf("read uint16 failed, offset: %d", offset)
	}
	*msg = binary.LittleEndian.Uint16(decoder.buffer[offset : offset+sizeint16])
	decoder.cursor += sizeint16
	return nil
}

func (decoder *EbpfDecoder) DecodeUint16BigEndian(msg *uint16) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < sizeint16 {
		return fmt.Errorf("read uint16BE failed, offset: %d", offset)
	}
	*msg = binary.BigEndian.Uint16(decoder.buffer[offset : offset+sizeint16])
	decoder.cursor += sizeint16
	return nil
}

func (decoder *EbpfDecoder) DecodeInt32(msg *int32) error {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return fmt.Errorf("read int32 failed, offset: %d", offset)
	}
	*msg = int32(binary.LittleEndian.Uint32(decoder.buffer[offset : offset+readAmount]))
	decoder.cursor += readAmount
	return nil
}

func (decoder *EbpfDecoder) DecodeUint32(msg *uint32) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < sizeint32 {
		return fmt.Errorf("read uint32 failed, offset: %d", offset)
	}
	*msg = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+sizeint32])
	decoder.cursor += sizeint32
	return nil
}

func (decoder *EbpfDecoder) DecodeUint32BigEndian(msg *uint32) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < sizeint32 {
		return fmt.Errorf("read uint32BE failed, offset: %d", offset)
	}
	*msg = binary.BigEndian.Uint32(decoder.buffer[offset : offset+sizeint32])
	decoder.cursor += sizeint32
	return nil
}

func (decoder *EbpfDecoder) DecodeInt64(msg *int64) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < sizeint64 {
		return fmt.Errorf("read int64 failed, offset: %d", offset)
	}
	*msg = int64(binary.LittleEndian.Uint64(decoder.buffer[decoder.cursor : decoder.cursor+sizeint64]))
	decoder.cursor += sizeint64
	return nil
}

func (decoder *EbpfDecoder) DecodeUint64(msg *uint64) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < sizeint64 {
		return fmt.Errorf("read uint64 failed, offset: %d", offset)
	}
	*msg = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+sizeint64])
	decoder.cursor += sizeint64
	return nil
}

func (decoder *EbpfDecoder) DecodeBytes(msg []byte, size uint32) error {
	offset := decoder.cursor
	castedSize := int(size)
	if len(decoder.buffer[offset:]) < castedSize {
		return fmt.Errorf("read bytes failed, offset: %d", offset)
	}
	_ = copy(msg[:], decoder.buffer[offset:offset+castedSize])
	decoder.cursor += castedSize
	return nil
}

func (decoder *EbpfDecoder) DecodeString() (s string, err error) {
	var size int32
	if err = decoder.DecodeUint8(&decoder.index); err != nil {
		return
	}
	if err = decoder.DecodeInt32(&size); err != nil {
		return
	}
	// precheck size
	if size >= 8192 {
		err = errors.New(fmt.Sprintf("string size too long, size: %d", size))
		return
	}
	buf := share.BufferPool.Get()
	defer buf.Free()
	if err = decoder.DecodeBytes(buf.Bytes()[:size-1], uint32(size-1)); err != nil {
		return
	}
	decoder.DecodeUint8(&dummy)
	s = string(buf.Bytes()[:size-1])
	return
}

func (decoder *EbpfDecoder) DecodeRemoteAddr() (family, port uint16, addr string, err error) {
	var (
		_addr uint32
	)
	if err = decoder.DecodeUint8(&decoder.index); err != nil {
		return
	}
	if err = decoder.DecodeUint16(&family); err != nil {
		return
	}
	switch family {
	case 0, 2:
		if err = decoder.DecodeUint16BigEndian(&port); err != nil {
			return
		}
		if err = decoder.DecodeUint32BigEndian(&_addr); err != nil {
			return
		}
		addr = helper.PrintUint32IP(_addr)
		_, err = decoder.ReadByteSliceFromBuff(8)
	case 10:
		if decoder.DecodeUint16BigEndian(&port); err != nil {
			return
		}
		var _flowinfo uint32
		if decoder.DecodeUint32BigEndian(&_flowinfo); err != nil {
			return
		}
		var _addrtmp []byte
		_addrtmp, err = decoder.ReadByteSliceFromBuff(16)
		if err != nil {
			return
		}
		addr = helper.Print16BytesSliceIP(_addrtmp)
		// reuse
		if err = decoder.DecodeUint32BigEndian(&_flowinfo); err != nil {
			return
		}
	}
	return
}

func (decoder *EbpfDecoder) DecodePidTree(privilege_flag *uint8) (pidtree string, err error) {
	var (
		size uint8
		sz   uint32
		pid  uint32
		str  string
	)
	if err = decoder.DecodeUint8(&decoder.index); err != nil {
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
		if str, err = decoder.decodeStr(sz - 1); err != nil {
			break
		}
		strArr = append(strArr, strconv.FormatUint(uint64(pid), 10)+"."+str)
		decoder.DecodeUint8(&dummy)
	}
	pidtree = strings.Join(strArr, "<")
	// We add a cred check here...
	// get the privileged flag here
	if err = decoder.DecodeUint8(privilege_flag); err != nil {
		return
	}
	// if privilege_flag is set, get the creds
	// just testing code here...
	if *privilege_flag == 1 {
		var old = NewSlimCred()
		var new = NewSlimCred()
		defer PutSlimCred(old)
		defer PutSlimCred(new)
		if err = decoder.DecodeUint8(&decoder.index); err != nil {
			return
		}
		if err = decoder.DeocdeSlimCred(old); err != nil {
			return
		}
		if err = decoder.DecodeUint8(&decoder.index); err != nil {
			return
		}
		if err = decoder.DeocdeSlimCred(new); err != nil {
			return
		}
	}
	return
}

func (decoder *EbpfDecoder) DeocdeSlimCred(slimCred *SlimCred) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < 32 {
		return fmt.Errorf("can't read slimcred from buffer, offset: %d", offset)
	}
	slimCred.Uid = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+4])
	slimCred.Gid = binary.LittleEndian.Uint32(decoder.buffer[offset+4 : offset+8])
	slimCred.Suid = binary.LittleEndian.Uint32(decoder.buffer[offset+8 : offset+12])
	slimCred.Sgid = binary.LittleEndian.Uint32(decoder.buffer[offset+12 : offset+16])
	slimCred.Euid = binary.LittleEndian.Uint32(decoder.buffer[offset+16 : offset+20])
	slimCred.Egid = binary.LittleEndian.Uint32(decoder.buffer[offset+20 : offset+24])
	slimCred.Fsuid = binary.LittleEndian.Uint32(decoder.buffer[offset+24 : offset+28])
	slimCred.Fsgid = binary.LittleEndian.Uint32(decoder.buffer[offset+28 : offset+32])
	decoder.cursor += int(slimCred.GetSizeBytes())
	return nil
}

func (decoder *EbpfDecoder) DecodeStrArray() (strArr []string, err error) {
	var (
		size uint8
		str  string
		sz   uint32
	)
	if err = decoder.DecodeUint8(&decoder.index); err != nil {
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
		if str, err = decoder.decodeStr(sz - 1); err != nil {
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

func (decoder *EbpfDecoder) decodeStr(size uint32) (str string, err error) {
	offset := decoder.cursor
	castedSize := int(size)
	if len(decoder.buffer[offset:]) < castedSize {
		err = fmt.Errorf("read str failed, offset: %d, size: %d", offset, castedSize)
		return
	}
	str = string(decoder.buffer[offset : offset+castedSize])
	decoder.cursor += castedSize
	return
}
