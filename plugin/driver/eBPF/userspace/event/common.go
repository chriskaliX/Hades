package event

import (
	"encoding/binary"
	"io"
	"net"

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

func printUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

func Print16BytesSliceIP(in []byte) string {
	ip := net.IP(in)
	return ip.String()
}
