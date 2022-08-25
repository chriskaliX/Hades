package helper

import (
	"encoding/binary"
	"net"
)

const invaild = "-1"

func PrintUint32IP(in uint32) string {
	// as default, we do not return 0.0.0.0
	if in == 0 {
		return invaild
	}
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

func Print16BytesSliceIP(in []byte) string {
	if len(in) == 0 {
		return invaild
	}
	ip := net.IP(in)
	return ip.String()
}
