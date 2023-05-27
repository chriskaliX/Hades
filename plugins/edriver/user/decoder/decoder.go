// Decoder decodes the data from kernel space
// for better performance
package decoder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var DefaultDecoder = New(make([]byte, 0))
var ErrFilter = errors.New("filter")
var ErrIgnore = errors.New("ignore")

const (
	sizeint8    = 1
	sizeint16   = 2
	sizeint32   = 4
	sizeint64   = 8
	sizeContext = 168
	invalid     = "-1"
)

// eBPF events decoder, functions in this struct is not thread-safe
type EbpfDecoder struct {
	buffer []byte // raw buffer which is read from kern perf(or ringbuf)
	cursor int    // cursor of the buffer
	// internal values
	index       uint8 // index of the event, for less alloc since it's internal
	cache       []byte
	dummy       uint8
	innerBuffer [8192]byte
	eventCtx    *Context
	oldSlimCred *SlimCred
	newSlimCred *SlimCred
}

func New(rawBuffer []byte) *EbpfDecoder {
	return &EbpfDecoder{
		buffer:      rawBuffer,
		cursor:      0,
		cache:       make([]byte, 16),
		eventCtx:    &Context{},
		oldSlimCred: &SlimCred{},
		newSlimCred: &SlimCred{},
	}
}

// ReInit the decoder by accepting a new event buffer
func (d *EbpfDecoder) SetBuffer(_byte []byte) {
	d.buffer = append([]byte(nil), _byte...)
	d.cursor = 0
	d.index = 0
}

func (d *EbpfDecoder) BuffLen() int { return len(d.buffer) }

func (d *EbpfDecoder) GetContext() *Context { return d.eventCtx }

func (d *EbpfDecoder) ReadAmountBytes() int { return d.cursor }

func (d *EbpfDecoder) DecodeContext() (*Context, error) {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeContext {
		return nil, fmt.Errorf("can't read context from buffer: buffer too short")
	}
	d.eventCtx.StartTime = binary.LittleEndian.Uint64(d.buffer[offset : offset+8])
	d.eventCtx.StartTime = d.eventCtx.StartTime/1000000000 + bootTime
	d.eventCtx.CgroupID = binary.LittleEndian.Uint64(d.buffer[offset+8 : offset+16])
	d.eventCtx.Pns = binary.LittleEndian.Uint32(d.buffer[offset+16 : offset+20])
	d.eventCtx.Type = binary.LittleEndian.Uint32(d.buffer[offset+20 : offset+24])
	d.eventCtx.Pid = binary.LittleEndian.Uint32(d.buffer[offset+24 : offset+28])
	d.eventCtx.Tid = binary.LittleEndian.Uint32(d.buffer[offset+28 : offset+32])
	d.eventCtx.Uid = binary.LittleEndian.Uint32(d.buffer[offset+32 : offset+36])
	d.eventCtx.Gid = binary.LittleEndian.Uint32(d.buffer[offset+36 : offset+40])
	d.eventCtx.Ppid = binary.LittleEndian.Uint32(d.buffer[offset+40 : offset+44])
	d.eventCtx.Pgid = binary.LittleEndian.Uint32(d.buffer[offset+44 : offset+48])
	d.eventCtx.SessionID = binary.LittleEndian.Uint32(d.buffer[offset+48 : offset+52])
	d.eventCtx.Comm = string(bytes.TrimRight(d.buffer[offset+52:offset+68], "\x00"))
	d.eventCtx.PComm = string(bytes.TrimRight(d.buffer[offset+68:offset+84], "\x00"))
	d.eventCtx.Nodename = string(bytes.Trim(d.buffer[offset+84:offset+148], "\x00"))
	d.eventCtx.RetVal = int64(binary.LittleEndian.Uint64(d.buffer[offset+152 : offset+160]))
	d.eventCtx.Argnum = uint8(binary.LittleEndian.Uint16(d.buffer[offset+160 : offset+168]))
	d.cursor += sizeContext
	return d.eventCtx, nil
}

func (d *EbpfDecoder) DecodeUint8(msg *uint8) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeint8 {
		return fmt.Errorf("read uint8 failed, offset: %d", offset)
	}
	*msg = d.buffer[d.cursor]
	d.cursor += sizeint8
	return nil
}

func (d *EbpfDecoder) DecodeInt16(msg *int16) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeint16 {
		return fmt.Errorf("read int16 failed, offset: %d", offset)
	}
	*msg = int16(binary.LittleEndian.Uint16(d.buffer[offset : offset+sizeint16]))
	d.cursor += sizeint16
	return nil
}

func (d *EbpfDecoder) DecodeUint16(msg *uint16) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeint16 {
		return fmt.Errorf("read uint16 failed, offset: %d", offset)
	}
	*msg = binary.LittleEndian.Uint16(d.buffer[offset : offset+sizeint16])
	d.cursor += sizeint16
	return nil
}

func (d *EbpfDecoder) DecodeUint16BigEndian(msg *uint16) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeint16 {
		return fmt.Errorf("read uint16BE failed, offset: %d", offset)
	}
	*msg = binary.BigEndian.Uint16(d.buffer[offset : offset+sizeint16])
	d.cursor += sizeint16
	return nil
}

func (d *EbpfDecoder) DecodeInt32(msg *int32) error {
	readAmount := 4
	offset := d.cursor
	if len(d.buffer[offset:]) < readAmount {
		return fmt.Errorf("read int32 failed, offset: %d", offset)
	}
	*msg = int32(binary.LittleEndian.Uint32(d.buffer[offset : offset+readAmount]))
	d.cursor += readAmount
	return nil
}

func (d *EbpfDecoder) DecodeUint32(msg *uint32) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeint32 {
		return fmt.Errorf("read uint32 failed, offset: %d", offset)
	}
	*msg = binary.LittleEndian.Uint32(d.buffer[offset : offset+sizeint32])
	d.cursor += sizeint32
	return nil
}

func (d *EbpfDecoder) DecodeUint32BigEndian(msg *uint32) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeint32 {
		return fmt.Errorf("read uint32BE failed, offset: %d", offset)
	}
	*msg = binary.BigEndian.Uint32(d.buffer[offset : offset+sizeint32])
	d.cursor += sizeint32
	return nil
}

func (d *EbpfDecoder) DecodeInt64(msg *int64) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeint64 {
		return fmt.Errorf("read int64 failed, offset: %d", offset)
	}
	*msg = int64(binary.LittleEndian.Uint64(d.buffer[d.cursor : d.cursor+sizeint64]))
	d.cursor += sizeint64
	return nil
}

func (d *EbpfDecoder) DecodeUint64(msg *uint64) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeint64 {
		return fmt.Errorf("read uint64 failed, offset: %d", offset)
	}
	*msg = binary.LittleEndian.Uint64(d.buffer[offset : offset+sizeint64])
	d.cursor += sizeint64
	return nil
}

func (d *EbpfDecoder) DecodeBytes(msg []byte, size uint32) error {
	offset := d.cursor
	castedSize := int(size)
	if len(d.buffer[offset:]) < castedSize {
		return fmt.Errorf("read bytes failed, offset: %d", offset)
	}
	_ = copy(msg[:], d.buffer[offset:offset+castedSize])
	d.cursor += castedSize
	return nil
}

func (d *EbpfDecoder) DecodeString() (s string, err error) {
	var size int32
	if err = d.DecodeUint8(&d.index); err != nil {
		return
	}
	if err = d.DecodeInt32(&size); err != nil {
		return
	}
	// precheck size
	if size >= 8192 {
		err = fmt.Errorf("string size too long, size: %d", size)
		return
	}
	if err = d.DecodeBytes(d.innerBuffer[:size-1], uint32(size-1)); err != nil {
		return
	}
	d.DecodeUint8(&d.dummy)
	s = string(d.innerBuffer[:size-1])
	return
}

func (d *EbpfDecoder) DecodeAddr() (family, sport, dport uint16, sip, dip string, err error) {
	// get family firstly
	if err = d.DecodeUint8(&d.index); err != nil {
		return
	}
	if err = d.DecodeUint16(&family); err != nil {
		return
	}
	if err = d.DecodeUint8(&d.index); err != nil {
		return
	}
	switch family {
	case 0, unix.AF_INET:
		// Pay attention to memory align
		var _addr uint32
		if err = d.DecodeUint32BigEndian(&_addr); err != nil {
			return
		}
		sip = d.DecodeUint32Ip(_addr)
		if err = d.DecodeUint16BigEndian(&sport); err != nil {
			return
		}
		d.ReadByteSliceFromBuff(2)
		if err = d.DecodeUint32BigEndian(&_addr); err != nil {
			return
		}
		dip = d.DecodeUint32Ip(_addr)
		if err = d.DecodeUint16BigEndian(&dport); err != nil {
			return
		}
		d.ReadByteSliceFromBuff(2)
	case unix.AF_INET6:
		// struct in6_addr {
		// 	union {
		// 		__u8 u6_addr8[16];
		// 		__be16 u6_addr16[8];
		// 		__be32 u6_addr32[4];
		// 	} in6_u;
		// };
		// typedef struct network_connection_v6 {
		// 	struct in6_addr local_address;
		// 	__u16 local_port;
		// 	struct in6_addr remote_address;
		// 	__u16 remote_port;
		// 	__u32 flowinfo;
		// 	__u32 scope_id;
		// } net_conn_v6_t;
		// local ip
		if err = d.DecodeBytes(d.cache, 16); err != nil {
			return
		}
		sip = d.DecodeSliceIp(d.cache)
		// local port
		if err = d.DecodeUint16BigEndian(&sport); err != nil {
			return
		}
		d.ReadByteSliceFromBuff(2)
		// remote ip
		if err = d.DecodeBytes(d.cache, 16); err != nil {
			return
		}
		dip = d.DecodeSliceIp(d.cache)
		// remote port
		if err = d.DecodeUint16BigEndian(&dport); err != nil {
			return
		}
		// Align and unused field clean up
		d.ReadByteSliceFromBuff(10)
	default:
		err = fmt.Errorf("family %d not support", family)
		return
	}
	return
}

func (d *EbpfDecoder) DecodePidTree(privilege_flag *uint8) (pidtree string, err error) {
	var size uint8
	var sz, pid uint32
	var str string
	if err = d.DecodeUint8(&d.index); err != nil {
		return
	}
	if err = d.DecodeUint8(&size); err != nil {
		return
	}
	strArr := make([]string, 0, 8)
	for i := 0; i < int(size); i++ {
		if err = d.DecodeUint32(&pid); err != nil {
			break
		}
		if err = d.DecodeUint32(&sz); err != nil {
			break
		}
		if str, err = d.decodeStr(sz - 1); err != nil {
			break
		}
		strArr = append(strArr, strconv.FormatUint(uint64(pid), 10)+"."+str)
		d.DecodeUint8(&d.dummy)
	}
	pidtree = strings.Join(strArr, "<")
	// We add a cred check here...
	// get the privileged flag here
	if err = d.DecodeUint8(privilege_flag); err != nil {
		return
	}
	// if privilege_flag is set, get the creds
	if *privilege_flag == 1 {
		if err = d.DecodeUint8(&d.index); err != nil {
			return
		}
		if err = d.DeocdeSlimCred(d.oldSlimCred); err != nil {
			return
		}
		if err = d.DecodeUint8(&d.index); err != nil {
			return
		}
		if err = d.DeocdeSlimCred(d.newSlimCred); err != nil {
			return
		}
	}
	return
}

func (d *EbpfDecoder) DeocdeSlimCred(slimCred *SlimCred) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < 32 {
		return fmt.Errorf("can't read slimcred from buffer, offset: %d", offset)
	}
	slimCred.Uid = binary.LittleEndian.Uint32(d.buffer[offset : offset+4])
	slimCred.Gid = binary.LittleEndian.Uint32(d.buffer[offset+4 : offset+8])
	slimCred.Suid = binary.LittleEndian.Uint32(d.buffer[offset+8 : offset+12])
	slimCred.Sgid = binary.LittleEndian.Uint32(d.buffer[offset+12 : offset+16])
	slimCred.Euid = binary.LittleEndian.Uint32(d.buffer[offset+16 : offset+20])
	slimCred.Egid = binary.LittleEndian.Uint32(d.buffer[offset+20 : offset+24])
	slimCred.Fsuid = binary.LittleEndian.Uint32(d.buffer[offset+24 : offset+28])
	slimCred.Fsgid = binary.LittleEndian.Uint32(d.buffer[offset+28 : offset+32])
	d.cursor += int(slimCred.GetSizeBytes())
	return nil
}

func (d *EbpfDecoder) DecodeStrArray() (strArr []string, err error) {
	var (
		size uint8
		str  string
		sz   uint32
	)
	if err = d.DecodeUint8(&d.index); err != nil {
		return
	}
	if err = d.DecodeUint8(&size); err != nil {
		return
	}
	strArr = make([]string, 0, 2)
	for i := 0; i < int(size); i++ {
		if err = d.DecodeUint32(&sz); err != nil {
			break
		}
		if str, err = d.decodeStr(sz - 1); err != nil {
			return
		}
		strArr = append(strArr, str)
		d.DecodeUint8(&d.dummy)
	}
	return
}

func (d *EbpfDecoder) ReadByteSliceFromBuff(len int) (res []byte, err error) {
	res = make([]byte, len)
	err = d.DecodeBytes(res[:], uint32(len))
	if err != nil {
		return nil, fmt.Errorf("error reading byte array: %v", err)
	}
	return res, nil
}

func (d *EbpfDecoder) decodeStr(size uint32) (str string, err error) {
	offset := d.cursor
	castedSize := int(size)
	if len(d.buffer[offset:]) < castedSize {
		err = fmt.Errorf("read str failed, offset: %d, size: %d", offset, castedSize)
		return
	}
	str = string(d.buffer[offset : offset+castedSize])
	d.cursor += castedSize
	return
}

// perf non-related fields
func (d *EbpfDecoder) DecodeUint32Ip(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

func (d *EbpfDecoder) DecodeSliceIp(in []byte) string {
	if len(in) == 0 {
		return invalid
	}
	ip := net.IP(in)
	return ip.String()
}
