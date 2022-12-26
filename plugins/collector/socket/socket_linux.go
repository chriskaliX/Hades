package socket

import (
	"bufio"
	"collector/cache/user"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// @TODO: /proc/net/packet
// https://github.com/osquery/osquery/blob/f9282c0f03d049e0f13670afa2cf8a87f8ddf0cc/osquery/filesystem/linux/proc.cpp
// osquery中用户态获取socket方式 https://github.com/osquery/osquery/blob/f9282c0f03d049e0f13670afa2cf8a87f8ddf0cc/osquery/tables/networking/linux/process_open_sockets.cpp
// 在 osquery issue 1094 中(https://github.com/osquery/osquery/issues/1094) 解释了为什么剔除了用 netlink 获取的方式
// 大致为 netlink 的方式在 CentOS/RHEL6 不稳定, 经常会 fallback
// 可以看到之前 readnetlink 他们也有出现 timeout 的情况 https://github.com/osquery/osquery/pull/543
// 其他相关 issue: https://github.com/osquery/osquery/issues/671

// In Elkeid, socket rebuild again for better performance. By the way, since there is no race condition
// of netlink function execution, no netlink socket singleton or lock is needed in such situation.
// The source code is from: https://github.com/vishvananda/netlink/blob/main/socket_linux.go
const (
	sizeofSocketID      = 0x30
	sizeofSocketRequest = sizeofSocketID + 0x8
	sizeofSocket        = sizeofSocketID + 0x18
	netlinkLimit        = 1500 // max socket we get from netlink
)

var (
	native       = nl.NativeEndian()
	networkOrder = binary.BigEndian
)

type readBuffer struct {
	Bytes []byte
	pos   int
}

func (b *readBuffer) Read() byte {
	c := b.Bytes[b.pos]
	b.pos++
	return c
}

func (b *readBuffer) Next(n int) []byte {
	s := b.Bytes[b.pos : b.pos+n]
	b.pos += n
	return s
}

// what we define
type Socket struct {
	DPort     uint16 `json:"dport"`
	SPort     uint16 `json:"sport"`
	DIP       net.IP `json:"dip"`
	SIP       net.IP `json:"sip"`
	Interface uint32 `json:"interface"`
	Family    uint8  `json:"family"`
	State     uint8  `json:"state"`
	UID       uint32 `json:"uid"`
	Username  string `json:"username"`
	Inode     uint32 `json:"inode"`
	PID       int    `json:"pid"`
	Cmdline   string `json:"cmdline"`
	Comm      string `json:"comm"`
	Type      uint8  `json:"type"`
}

type socketRequest struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	pad      uint8
	States   uint32
	ID       _socketID
}

type writeBuffer struct {
	Bytes []byte
	pos   int
}

func (b *writeBuffer) Write(c byte) {
	b.Bytes[b.pos] = c
	b.pos++
}

func (b *writeBuffer) Next(n int) []byte {
	s := b.Bytes[b.pos : b.pos+n]
	b.pos += n
	return s
}

func (r *socketRequest) Serialize() []byte {
	b := writeBuffer{Bytes: make([]byte, sizeofSocketRequest)}
	b.Write(r.Family)
	b.Write(r.Protocol)
	b.Write(r.Ext)
	b.Write(r.pad)
	native.PutUint32(b.Next(4), r.States)
	networkOrder.PutUint16(b.Next(2), r.ID.SourcePort)
	networkOrder.PutUint16(b.Next(2), r.ID.DestinationPort)
	if r.Family == unix.AF_INET6 {
		copy(b.Next(16), r.ID.Source)
		copy(b.Next(16), r.ID.Destination)
	} else {
		copy(b.Next(4), r.ID.Source.To4())
		b.Next(12)
		copy(b.Next(4), r.ID.Destination.To4())
		b.Next(12)
	}
	native.PutUint32(b.Next(4), r.ID.Interface)
	native.PutUint32(b.Next(4), r.ID.Cookie[0])
	native.PutUint32(b.Next(4), r.ID.Cookie[1])
	return b.Bytes
}

func (r *socketRequest) Len() int { return sizeofSocketRequest }

// Add limitation of socket, in case too much of this.
func parseNetlink(family, protocol uint8, state uint32) (sockets []Socket, err error) {
	var (
		s   *nl.NetlinkSocket
		req *nl.NetlinkRequest
	)
	// precheck protocol
	if protocol != unix.IPPROTO_UDP && protocol != unix.IPPROTO_TCP {
		err = fmt.Errorf("unsupported protocol %d", protocol)
		return
	}
	// subscribe the netlink
	if s, err = nl.Subscribe(unix.NETLINK_INET_DIAG); err != nil {
		return
	}
	defer s.Close()
	// send the netlink request
	req = nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(&socketRequest{
		Family:   family,
		Protocol: protocol,
		Ext:      (1 << (INET_DIAG_VEGASINFO - 1)) | (1 << (INET_DIAG_INFO - 1)),
		States:   uint32(1 << state),
	})
	if err = s.Send(req); err != nil {
		return
	}
loop:
	for i := 1; i < netlinkLimit; i++ {
		var msgs []syscall.NetlinkMessage
		var from *unix.SockaddrNetlink
		msgs, from, err = s.Receive()
		if err != nil {
			return
		}
		if from.Pid != nl.PidKernel {
			continue
		}
		if len(msgs) == 0 {
			break
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				break loop
			case unix.NLMSG_ERROR:
				break loop
			}
			sockInfo := &_socket{}
			if err := sockInfo.deserialize(m.Data); err != nil {
				continue
			}
			socket := Socket{
				SIP:       sockInfo.ID.Source,
				DIP:       sockInfo.ID.Destination,
				SPort:     sockInfo.ID.SourcePort,
				DPort:     sockInfo.ID.DestinationPort,
				UID:       sockInfo.UID,
				Interface: sockInfo.ID.Interface,
				Family:    sockInfo.Family,
				State:     sockInfo.State,
				Inode:     sockInfo.INode,
				Type:      protocol,
			}
			socket.Username = user.Cache.GetUser(socket.UID).Username
			sockets = append(sockets, socket)
		}
	}
	return
}

func parseIP(hexIP string) (net.IP, error) {
	var byteIP []byte
	byteIP, err := hex.DecodeString(hexIP)
	if err != nil {
		return nil, fmt.Errorf("cannot parse address field in socket line %q", hexIP)
	}
	switch len(byteIP) {
	case 4:
		return net.IP{byteIP[3], byteIP[2], byteIP[1], byteIP[0]}, nil
	case 16:
		i := net.IP{
			byteIP[3], byteIP[2], byteIP[1], byteIP[0],
			byteIP[7], byteIP[6], byteIP[5], byteIP[4],
			byteIP[11], byteIP[10], byteIP[9], byteIP[8],
			byteIP[15], byteIP[14], byteIP[13], byteIP[12],
		}
		return i, nil
	default:
		return nil, fmt.Errorf("unable to parse IP %s", hexIP)
	}
}

// Refernce: https://guanjunjian.github.io/2017/11/09/study-8-proc-net-tcp-analysis/
func parseProcNet(family, protocol uint8, path string) (sockets []Socket, err error) {
	var (
		file *os.File
		r    *bufio.Scanner
	)
	if file, err = os.Open(path); err != nil {
		return
	}
	defer file.Close()
	r = bufio.NewScanner(io.LimitReader(file, 1024*1024*2))
	header := make(map[int]string)
	for i := 0; r.Scan(); i++ {
		if i == 0 {
			header[0] = "sl"
			header[1] = "local_address"
			header[2] = "rem_address"
			header[3] = "st"
			header[4] = "queue"
			header[5] = "t"
			header[6] = "retrnsmt"
			header[7] = "uid"
			for index, field := range strings.Fields(r.Text()[strings.Index(r.Text(), "uid")+3:]) {
				header[8+index] = field
			}
		} else {
			socket := Socket{Family: family, Type: protocol}
			droped := false
			for index, key := range strings.Fields(r.Text()) {
				switch header[index] {
				case "local_address":
					fields := strings.Split(key, ":")
					if len(fields) != 2 {
						droped = true
						break
					}
					socket.SIP, err = parseIP(fields[0])
					if err != nil {
						droped = true
						break
					}
					var port uint64
					port, err = strconv.ParseUint(fields[1], 16, 64)
					if err != nil {
						droped = true
						break
					}
					socket.SPort = uint16(port)
				case "rem_address":
					fields := strings.Split(key, ":")
					if len(fields) != 2 {
						droped = true
						break
					}
					socket.DIP, err = parseIP(fields[0])
					if err != nil {
						droped = true
						break
					}
					var port uint64
					port, err = strconv.ParseUint(fields[1], 16, 64)
					if err != nil {
						droped = true
						break
					}
					socket.DPort = uint16(port)
				case "st":
					st, err := strconv.ParseUint(key, 16, 64)
					if err != nil {
						continue
					}
					if protocol == unix.IPPROTO_UDP && st != 7 {
						droped = true
						break
					}
					// in Elkeid, st is only for listen. Since Elkeid get the LKM driver to get any socket_connect
					// they want. But in Hades, socket things can only be get properly by ebpf. Otherwise, we can
					// just can collect those things like osquery. We get TCP_ESTABLISHED and TCP_LISTEN
					// TCP_ESTABLISHED:1   TCP_SYN_SENT:2
					// TCP_SYN_RECV:3      TCP_FIN_WAIT1:4
					// TCP_FIN_WAIT2:5     TCP_TIME_WAIT:6
					// TCP_CLOSE:7         TCP_CLOSE_WAIT:8
					// TCP_LAST_ACL:9      TCP_LISTEN:10
					// TCP_CLOSING:11
					if protocol == unix.IPPROTO_TCP && (st != 10 && st != 1) {
						droped = true
						break
					}
					socket.State = uint8(st)
				case "uid":
					uid, err := strconv.ParseUint(key, 0, 64)
					if err != nil {
						continue
					}
					socket.UID = uint32(uid)
					socket.Username = user.Cache.GetUser(uint32(uid)).Username
				case "inode":
					inode, err := strconv.ParseUint(key, 0, 64)
					if err != nil {
						continue
					}
					socket.Inode = uint32(inode)
				default:
				}
			}
			if !droped && len(socket.DIP) != 0 && len(socket.SIP) != 0 && socket.State != 0 {
				sockets = append(sockets, socket)
			}
		}
	}
	return
}

// add limitation of this
func FromProc() (sockets []Socket, err error) {
	tcpSocks, err := parseProcNet(unix.AF_INET, unix.IPPROTO_TCP, "/proc/net/tcp")
	if err != nil {
		return
	}
	sockets = append(sockets, tcpSocks...)
	tcp6Socks, err := parseProcNet(unix.AF_INET6, unix.IPPROTO_TCP, "/proc/net/tcp6")
	if err == nil {
		sockets = append(sockets, tcp6Socks...)
	}
	udpSocks, err := parseProcNet(unix.AF_INET, unix.IPPROTO_UDP, "/proc/net/udp")
	if err == nil {
		sockets = append(sockets, udpSocks...)
	}
	udp6Socks, err := parseProcNet(unix.AF_INET6, unix.IPPROTO_UDP, "/proc/net/udp6")
	if err == nil {
		sockets = append(sockets, udp6Socks...)
	}
	inodeMap := make(map[uint32]int)
	for index, socket := range sockets {
		if socket.Inode != 0 {
			inodeMap[socket.Inode] = index
		}
	}
	return
}

func FromNetlink() (sockets []Socket, err error) {
	var udpSockets, udp6Sockets, tcpSockets, tcp6Sockets []Socket
	udpSockets, err = parseNetlink(unix.AF_INET, unix.IPPROTO_UDP, 7)
	if err != nil {
		return
	}
	sockets = append(sockets, udpSockets...)
	udp6Sockets, err = parseNetlink(unix.AF_INET6, unix.IPPROTO_UDP, 7)
	if err != nil {
		return
	}
	// TCP - sockets for both established & listen, any better for state? dig out this
	sockets = append(sockets, udp6Sockets...)
	tcpSockets, err = parseNetlink(unix.AF_INET, unix.IPPROTO_TCP, 1)
	if err != nil {
		return
	}
	sockets = append(sockets, tcpSockets...)
	tcpSockets, err = parseNetlink(unix.AF_INET, unix.IPPROTO_TCP, 10)
	if err != nil {
		return
	}
	sockets = append(sockets, tcpSockets...)
	tcp6Sockets, err = parseNetlink(unix.AF_INET6, unix.IPPROTO_TCP, 1)
	if err != nil {
		return
	}
	sockets = append(sockets, tcp6Sockets...)
	tcp6Sockets, err = parseNetlink(unix.AF_INET6, unix.IPPROTO_TCP, 10)
	if err != nil {
		return
	}
	sockets = append(sockets, tcp6Sockets...)
	return
}

// To learn the way osquery get sockets, we go through the source code of osquery
// 1. Collect all sockets from from /proc/<pid>/fd and search for the links of
//    type of socket:[<inode>], and we get the relationship of pid - inode(socket)
// 2. Get <pid> ns/net -> inode, execute step 3 every time once a new inode is found
// 3. Get & parse the tcp/tcp6/udp/udp6 from /net/ of every pid.
//
// https://github.com/osquery/osquery/pull/608, as metioned in this pull request.
// netlink is somehow faster than /proc/ way.
