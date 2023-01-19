package decoder

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeContext(t *testing.T) {
	// success
	// context
	buf := []byte{
		1, 1, 1, 1, 1, 1, 1, 1, // starttime
		1, 0, 0, 0, 0, 0, 0, 0, // cgroupid
		2, 0, 0, 0, // pns
		3, 0, 0, 0, // type
		4, 0, 0, 0, // pid
		5, 0, 0, 0, // tid
		6, 0, 0, 0, // uid
		7, 0, 0, 0, // gid
		8, 0, 0, 0, // ppid
		9, 0, 0, 0, // pgid
		10, 0, 0, 0, // sessionid
		108, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // comm
		98, 97, 115, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // pcomm
		117, 98, 117, 110, 116, 117, // nodename
	}
	empty := make([]byte, 62)
	buf = append(buf, empty...)
	buf = append(buf, []byte{
		11, 0, 0, 0, 0, 0, 0, 0, // retval
		12, 0, 0, 0, 0, 0, 0, 0, // argnum
	}...)
	// pid tree (without privilege)
	pid_tree := []byte{
		0,          // index
		2,          // count
		2, 0, 0, 0, // pid_1
		3, 0, 0, 0, // size_1
		108, 115, 0, // ls
		1, 0, 0, 0, // pid_2
		5, 0, 0, 0, // size_2
		98, 97, 115, 104, 0, // bash
		0, //privilege_flag
	}
	// pid tree (with privilege)
	pid_tree_priv := []byte{
		0,          // index
		2,          // count
		2, 0, 0, 0, // pid_1
		3, 0, 0, 0, // size_1
		108, 115, 0, // ls
		1, 0, 0, 0, // pid_2
		5, 0, 0, 0, // size_2
		98, 97, 115, 104, 0, // bash
		1, //privilege_flag
		0, // index
		// old slim
		1, 0, 0, 0,
		2, 0, 0, 0,
		3, 0, 0, 0,
		4, 0, 0, 0,
		5, 0, 0, 0,
		6, 0, 0, 0,
		7, 0, 0, 0,
		8, 0, 0, 0,
		1, // index
		// new slim
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	buf = append(buf, pid_tree...)
	buf = append(buf, pid_tree_priv...)

	DefaultDecoder.SetBuffer(buf)
	var context *Context
	var err error
	// context
	if context, err = DefaultDecoder.DecodeContext(); err != nil {
		t.Fatal(err)
	}
	// assert.Equal(t, context.StartTime, uint64(1746437716), "starttime should be the same")
	assert.Equal(t, context.CgroupID, uint64(1))
	assert.Equal(t, context.Pns, uint32(2))
	assert.Equal(t, context.Type, uint32(3))
	assert.Equal(t, context.Pid, uint32(4))
	assert.Equal(t, context.Tid, uint32(5))
	assert.Equal(t, context.Uid, uint32(6))
	assert.Equal(t, context.Gid, uint32(7))
	assert.Equal(t, context.Ppid, uint32(8))
	assert.Equal(t, context.Pgid, uint32(9))
	assert.Equal(t, context.SessionID, uint32(10))
	assert.Equal(t, context.Comm, "ls")
	assert.Equal(t, context.PComm, "bash")
	assert.Equal(t, context.Nodename, "ubuntu")
	assert.Equal(t, context.RetVal, int64(11))
	assert.Equal(t, context.Argnum, uint8(12))

	var privilege_flag uint8
	// pid tree decode
	var pid_tree_str string
	if pid_tree_str, err = DefaultDecoder.DecodePidTree(&privilege_flag); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, pid_tree_str, "2.ls<1.bash")
	if pid_tree_str, err = DefaultDecoder.DecodePidTree(&privilege_flag); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, pid_tree_str, "2.ls<1.bash")
	// fail
	buf = []byte{
		1, 1, 1, 1, 1, 1, 1, 1, // starttime
		1, 0, 0, 0, 0, 0, 0, 0, // cgroupid
		2, 0, 0, 0, // pns
		3, 0, 0, 0, // type
		4, 0, 0, 0, // pid
		5, 0, 0, 0, // tid
		6, 0, 0, 0, // uid
		7, 0, 0, 0, // gid
		8, 0, 0, 0, // ppid
		9, 0, 0, 0, // pgid
		10, 0, 0, 0, // sessionid
		108, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // comm
		98, 97, 115, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // pcomm
		117, 98, 117, 110, 116, 117, // nodename
	}
	DefaultDecoder.SetBuffer(buf)
	DefaultDecoder.ReadByteSliceFromBuff(2)
	if _, err = DefaultDecoder.DecodeContext(); err == nil {
		t.Fatal("DecodeContext should fail")
	}
}

func TestDecodeUint8(t *testing.T) {
	// success
	var i uint8
	DefaultDecoder.SetBuffer(make([]byte, 1))
	if err := DefaultDecoder.DecodeUint8(&i); err != nil {
		t.Fatal(i)
	}
	// fail
	DefaultDecoder.SetBuffer(make([]byte, 0))
	if err := DefaultDecoder.DecodeUint8(&i); err == nil {
		t.Fatal("TestDecodeUint8 should fail")
	}
}

func TestDecodeInt16(t *testing.T) {
	// success
	var i int16
	DefaultDecoder.SetBuffer(make([]byte, 2))
	if err := DefaultDecoder.DecodeInt16(&i); err != nil {
		t.Fatal(i)
	}
	// fail
	DefaultDecoder.SetBuffer(make([]byte, 0))
	if err := DefaultDecoder.DecodeInt16(&i); err == nil {
		t.Fatal("TestDecodeint16 should fail")
	}
}

func TestDecodeUint16(t *testing.T) {
	// success
	var i uint16
	DefaultDecoder.SetBuffer(make([]byte, 2))
	if err := DefaultDecoder.DecodeUint16(&i); err != nil {
		t.Fatal(i)
	}
	// fail
	DefaultDecoder.SetBuffer(make([]byte, 0))
	if err := DefaultDecoder.DecodeUint16(&i); err == nil {
		t.Fatal("TestDecodeUint16 should fail")
	}
}

func TestDecodeUint16BigEndian(t *testing.T) {
	// success
	var i uint16
	DefaultDecoder.SetBuffer(make([]byte, 2))
	if err := DefaultDecoder.DecodeUint16BigEndian(&i); err != nil {
		t.Fatal(i)
	}
	// fail
	DefaultDecoder.SetBuffer(make([]byte, 0))
	if err := DefaultDecoder.DecodeUint16BigEndian(&i); err == nil {
		t.Fatal("TestDecodeUint16 should fail")
	}
}

func TestDecodeInt32(t *testing.T) {
	// success
	var i int32
	DefaultDecoder.SetBuffer(make([]byte, 4))
	if err := DefaultDecoder.DecodeInt32(&i); err != nil {
		t.Fatal(i)
	}
	// fail
	DefaultDecoder.SetBuffer(make([]byte, 0))
	if err := DefaultDecoder.DecodeInt32(&i); err == nil {
		t.Fatal("TestDecodeInt32 should fail")
	}
}

func TestDecodeUint32(t *testing.T) {
	// success
	var i uint32
	DefaultDecoder.SetBuffer(make([]byte, 4))
	if err := DefaultDecoder.DecodeUint32(&i); err != nil {
		t.Fatal(i)
	}
	// fail
	DefaultDecoder.SetBuffer(make([]byte, 0))
	if err := DefaultDecoder.DecodeUint32(&i); err == nil {
		t.Fatal("TestDecodeUint32 should fail")
	}
}

func TestDecodeUint32BigEndian(t *testing.T) {
	// success
	var i uint32
	DefaultDecoder.SetBuffer(make([]byte, 4))
	if err := DefaultDecoder.DecodeUint32BigEndian(&i); err != nil {
		t.Fatal(i)
	}
	// fail
	DefaultDecoder.SetBuffer(make([]byte, 0))
	if err := DefaultDecoder.DecodeUint32BigEndian(&i); err == nil {
		t.Fatal("Uint32BigEndian should fail")
	}
}

func TestDecodeInt64(t *testing.T) {
	// success
	var i int64
	DefaultDecoder.SetBuffer(make([]byte, 8))
	if err := DefaultDecoder.DecodeInt64(&i); err != nil {
		t.Fatal(i)
	}
	// fail
	DefaultDecoder.SetBuffer(make([]byte, 0))
	if err := DefaultDecoder.DecodeInt64(&i); err == nil {
		t.Fatal("TestDecodeInt64 should fail")
	}
}

func TestDecodeUint64(t *testing.T) {
	// success
	var i uint64
	DefaultDecoder.SetBuffer(make([]byte, 8))
	if err := DefaultDecoder.DecodeUint64(&i); err != nil {
		t.Fatal(i)
	}
	// fail
	DefaultDecoder.SetBuffer(make([]byte, 0))
	if err := DefaultDecoder.DecodeUint64(&i); err == nil {
		t.Fatal("TestDecodeUint64 should fail")
	}
}

func TestDecodeBytes(t *testing.T) {
	// success
	var i uint64
	DefaultDecoder.SetBuffer(make([]byte, 4))
	recv := []byte{1, 1, 1, 1}
	if err := DefaultDecoder.DecodeBytes(recv, 4); err != nil {
		t.Fatal(i)
	}
	assert.Equal(t, recv, []byte{0, 0, 0, 0})
	// fail
	DefaultDecoder.SetBuffer(make([]byte, 4))
	if err := DefaultDecoder.DecodeBytes(recv, 8); err == nil {
		t.Fatal("DecodeBytes should fail")
	}
}

func TestDecodeString(t *testing.T) {
	// success
	buf := []byte{
		0,          // index
		3, 0, 0, 0, // size
		108, 115, 0,
	}
	DefaultDecoder.SetBuffer(buf)
	str, err := DefaultDecoder.DecodeString()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, str, "ls")
	// fail_1
	buf = []byte{
		0,           // index
		1, 32, 0, 0, // size
	}
	buf = append(buf, make([]byte, 8193)...)
	DefaultDecoder.SetBuffer(buf)
	_, err = DefaultDecoder.DecodeString()
	if err == nil {
		t.Fatal(err)
	}
	// fail_2
	buf = []byte{
		0,           // index
		10, 0, 0, 0, // size
	}
	buf = append(buf, make([]byte, 5)...)
	DefaultDecoder.SetBuffer(buf)
	_, err = DefaultDecoder.DecodeString()
	if err == nil {
		t.Fatal(err)
	}
}

func TestDecodeUint32Ip(t *testing.T) {
	ip := uint32(3232235521)
	assert.Equal(t, DefaultDecoder.DecodeUint32Ip(ip), "192.168.0.1")
	assert.Equal(t, DefaultDecoder.DecodeSliceIp([]byte{192, 168, 0, 1}), "192.168.0.1")
}

func TestDecodeAddr(t *testing.T) {
	// IPV4
	buf := []byte{
		0,    // index
		2, 0, // family
		0,              // index
		192, 168, 1, 1, // sip
		0, 80, // sport
		0, 0, // padding
		192, 168, 2, 1, // dip
		1, 187, // dport
		0, 0, // padding
	}
	DefaultDecoder.SetBuffer(buf)
	family, sport, dport, sip, dip, err := DefaultDecoder.DecodeAddr()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, family, uint16(2))
	assert.Equal(t, sip, "192.168.1.1")
	assert.Equal(t, sport, uint16(80))
	assert.Equal(t, dip, "192.168.2.1")
	assert.Equal(t, dport, uint16(443))

	ip := net.ParseIP("2001:db8::68")
	t.Log(ip.MarshalText())

	// IPV6
	buf = []byte{
		0,     // index
		10, 0, // family
		0,                                                             // index
		32, 1, 13, 184, 18, 52, 0, 1, 2, 34, 21, 255, 254, 63, 181, 8, // sip
		0, 80, // sport
		0, 0, // padding
		50, 48, 48, 49, 58, 100, 98, 56, 58, 58, 54, 56, 0, 0, 0, 0, // dip
		1, 187, // dport
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // padding
	}
	DefaultDecoder.SetBuffer(buf)
	family, sport, dport, sip, dip, err = DefaultDecoder.DecodeAddr()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, family, uint16(10))
	assert.Equal(t, sport, uint16(80))
	assert.Equal(t, dport, uint16(443))
	assert.Equal(t, sip, "2001:db8:1234:1:222:15ff:fe3f:b508")
	assert.Equal(t, dip, "3230:3031:3a64:6238:3a3a:3638::")

	// INVALID
	buf = []byte{
		0,     // index
		11, 0, // family
		0,                                                             // index
		32, 1, 13, 184, 18, 52, 0, 1, 2, 34, 21, 255, 254, 63, 181, 8, // sip
		0, 80, // sport
		0, 0, // padding
		50, 48, 48, 49, 58, 100, 98, 56, 58, 58, 54, 56, 0, 0, 0, 0, // dip
		1, 187, // dport
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // padding
	}
	DefaultDecoder.SetBuffer(buf)
	_, _, _, _, _, err = DefaultDecoder.DecodeAddr()
	if err.Error() != "family 11 not support" {
		t.Fatal(err)
	}
}

func TestDecodeStrArray(t *testing.T) {
	buf := []byte{
		0,          //index
		2,          //count
		3, 0, 0, 0, // string size
		108, 115, 0, // ls
		5, 0, 0, 0, // string size
		98, 97, 115, 104, 0, // bash
	}
	DefaultDecoder.SetBuffer(buf)
	strArr, err := DefaultDecoder.DecodeStrArray()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, strArr[0], "ls")
	assert.Equal(t, strArr[1], "bash")
}

func TestReadByteSliceFromBuff(t *testing.T) {
	// success
	buf := []byte{
		1, 2, 3, 4,
	}
	DefaultDecoder.SetBuffer(buf)
	res, err := DefaultDecoder.ReadByteSliceFromBuff(4)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, res, buf)
	// fail
	DefaultDecoder.SetBuffer(buf)
	_, err = DefaultDecoder.ReadByteSliceFromBuff(8)
	if err == nil {
		t.Fatal("ReadByteSliceFromBuff should fail")
	}
}

func TestBasicFunc(t *testing.T) {
	// BuffLen
	buf := []byte{0, 0, 0, 0}
	DefaultDecoder.SetBuffer(buf)
	assert.Equal(t, DefaultDecoder.BuffLen(), 4)
	DefaultDecoder.GetContext()
	assert.Equal(t, DefaultDecoder.ReadAmountBytes(), 0)

}
