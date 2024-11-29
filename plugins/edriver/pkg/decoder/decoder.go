// Decoder decodes the data from kernel space for better performance
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

var ErrBufferTooShort = errors.New("can't read context from buffer: buffer too short")

var DefaultDecoder = New(make([]byte, 0))
var ErrFilter = errors.New("filter")
var ErrIgnore = errors.New("ignore")

const (
	sizeInt8    = 1
	sizeInt16   = 2
	sizeInt32   = 4
	sizeInt64   = 8
	sizeContext = 168
	invalid     = "-1"
)

// eBPF events decoder, functions in this struct is not thread-safe
type EbpfDecoder struct {
	buffer 		[]byte // raw buffer which is read from kern perf(or ringbuf)
	cursor 		int    // cursor of the buffer
	index       uint8  // index of the event, for less alloc since it's internal
	cache       []byte
	dummy       uint8
	innerBuffer [8192]byte
	eventCtx    *Context
	oldSlimCred *SlimCred
	newSlimCred *SlimCred
}

// New creates a new EbpfDecoder instance with a given raw buffer.
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

// SetBuffer initializes the decoder with a new event buffer.
func (d *EbpfDecoder) SetBuffer(newBuffer []byte) {
	d.buffer = append([]byte(nil), newBuffer...)
	d.cursor = 0
	d.index = 0
}

// BuffLen returns the length of the buffer.
func (d *EbpfDecoder) BuffLen() int { return len(d.buffer) }

// GetContext returns the current event context.
func (d *EbpfDecoder) GetContext() *Context { return d.eventCtx }

// ReadAmountBytes returns the number of bytes that have been read.
func (d *EbpfDecoder) ReadAmountBytes() int { return d.cursor }

// DecodeContext decodes the context from the buffer.
func (d *EbpfDecoder) DecodeContext() (*Context, error) {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeContext {
		return nil, ErrBufferTooShort
	}

	// Decode fields into the event context
	d.eventCtx.StartTime = binary.LittleEndian.Uint64(d.buffer[offset : offset+8]) / 1000000000 + bootTime
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

// DecodeUint8 decodes a uint8 from the buffer.
func (d *EbpfDecoder) DecodeUint8(msg *uint8) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeInt8 {
		return ErrBufferTooShort
	}
	*msg = d.buffer[d.cursor]
	d.cursor += sizeInt8
	return nil
}

// DecodeInt16 decodes an int16 from the buffer.
func (d *EbpfDecoder) DecodeInt16(msg *int16) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeInt16 {
		return ErrBufferTooShort
	}
	*msg = int16(binary.LittleEndian.Uint16(d.buffer[offset : offset+sizeInt16]))
	d.cursor += sizeInt16
	return nil
}

// DecodeUint16 decodes a uint16 from the buffer.
func (d *EbpfDecoder) DecodeUint16(msg *uint16) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeInt16 {
		return ErrBufferTooShort
	}
	*msg = binary.LittleEndian.Uint16(d.buffer[offset : offset+sizeInt16])
	d.cursor += sizeInt16
	return nil
}

// DecodeUint16BigEndian decodes a uint16 in big-endian format from the buffer.
func (d *EbpfDecoder) DecodeUint16BigEndian(msg *uint16) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeInt16 {
		return ErrBufferTooShort
	}
	*msg = binary.BigEndian.Uint16(d.buffer[offset : offset+sizeInt16])
	d.cursor += sizeInt16
	return nil
}

// DecodeInt32 decodes an int32 from the buffer.
func (d *EbpfDecoder) DecodeInt32(msg *int32) error {
	readAmount := 4
	offset := d.cursor
	if len(d.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = int32(binary.LittleEndian.Uint32(d.buffer[offset : offset+readAmount]))
	d.cursor += readAmount
	return nil
}

// DecodeUint32 decodes a uint32 from the buffer.
func (d *EbpfDecoder) DecodeUint32(msg *uint32) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeInt32 {
		return ErrBufferTooShort
	}
	*msg = binary.LittleEndian.Uint32(d.buffer[offset : offset+sizeInt32])
	d.cursor += sizeInt32
	return nil
}

// DecodeUint32BigEndian decodes a uint32 in big-endian format from the buffer.
func (d *EbpfDecoder) DecodeUint32BigEndian(msg *uint32) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeInt32 {
		return ErrBufferTooShort
	}
	*msg = binary.BigEndian.Uint32(d.buffer[offset : offset+sizeInt32])
	d.cursor += sizeInt32
	return nil
}

// DecodeInt64 decodes an int64 from the buffer.
func (d *EbpfDecoder) DecodeInt64(msg *int64) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeInt64 {
		return ErrBufferTooShort
	}
	*msg = int64(binary.LittleEndian.Uint64(d.buffer[d.cursor : d.cursor+sizeInt64]))
	d.cursor += sizeInt64
	return nil
}

// DecodeUint64 decodes a uint64 from the buffer.
func (d *EbpfDecoder) DecodeUint64(msg *uint64) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < sizeInt64 {
		return ErrBufferTooShort
	}
	*msg = binary.LittleEndian.Uint64(d.buffer[offset : offset+sizeInt64])
	d.cursor += sizeInt64
	return nil
}

// DecodeBytes decodes a byte slice of a specified size from the buffer.
func (d *EbpfDecoder) DecodeBytes(msg []byte, size uint32) error {
	offset := d.cursor
	castedSize := int(size)
	if len(d.buffer[offset:]) < castedSize {
		return ErrBufferTooShort
	}
	_ = copy(msg[:], d.buffer[offset:offset+castedSize])
	d.cursor += castedSize
	return nil
}

// DecodeString decodes a null-terminated string from the buffer.
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

// DecodePath decodes a file path from the buffer.
func (d *EbpfDecoder) DecodePath() (s string, err error) {
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
	d.DecodeUint8(&d.dummy) // index, trivial
	s = string(d.innerBuffer[:size-1])
	// NOTICE: for now, only ugly hardcode, will be better
	if s == "pipe:" || s == "socket:" {
		d.DecodeUint8(&d.dummy)
		var inode uint64
		if err = d.DecodeUint64(&inode); err != nil {
			return
		}
		s = s + "[" + strconv.FormatUint(inode, 10) + "]"
	}
	return
}

// DecodeAddr decodes an address from the buffer, returning family, source port, destination port, and IPs.
func (d *EbpfDecoder) DecodeAddr() (family, sport, dport uint16, sip, dip string, err error) {
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

// DecodePidTree decodes the PID tree from the buffer.
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
		strArr = append(strArr, fmt.Sprintf("%d.%s", pid, str))
		d.DecodeUint8(&d.dummy)
	}

	pidtree = strings.Join(strArr, "<")

	if err = d.DecodeUint8(privilege_flag); err != nil {
		return
	}
	// if privilege_flag is set, get the creds
	if *privilege_flag == 1 {
		if err = d.DecodeUint8(&d.index); err != nil {
			return
		}
		if err = d.DecodeSlimCred(d.oldSlimCred); err != nil {
			return
		}
		if err = d.DecodeUint8(&d.index); err != nil {
			return
		}
		if err = d.DecodeSlimCred(d.newSlimCred); err != nil {
			return
		}
	}
	return
}

// DecodeSlimCred decodes slim credentials from the buffer.
func (d *EbpfDecoder) DecodeSlimCred(slimCred *SlimCred) error {
	offset := d.cursor
	if len(d.buffer[offset:]) < 32 {
		return ErrBufferTooShort
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

// DecodeStrArray decodes an array of strings from the buffer.
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

// ReadByteSliceFromBuff reads a slice of bytes from the buffer.
func (d *EbpfDecoder) ReadByteSliceFromBuff(len int) (res []byte, err error) {
	res = make([]byte, len)
	err = d.DecodeBytes(res[:], uint32(len))
	if err != nil {
		return nil, fmt.Errorf("error reading byte array: %v", err)
	}
	return res, nil
}

// decodeStr decodes a string of specified size from the buffer.
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

// DecodeUint32Ip converts a uint32 IP address to a string.
func (d *EbpfDecoder) DecodeUint32Ip(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

// DecodeSliceIp converts a byte slice IP address to a string.
func (d *EbpfDecoder) DecodeSliceIp(in []byte) string {
	if len(in) == 0 {
		return invalid
	}
	ip := net.IP(in)
	return ip.String()
}
