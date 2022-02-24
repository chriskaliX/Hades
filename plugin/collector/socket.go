package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"collector/cache"
	"collector/network"
	"collector/share"

	"github.com/chriskaliX/plugin"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink/nl"
)

// @TODO: /proc/net/packet
// https://github.com/osquery/osquery/blob/f9282c0f03d049e0f13670afa2cf8a87f8ddf0cc/osquery/filesystem/linux/proc.cpp
// osquery中用户态获取socket方式 https://github.com/osquery/osquery/blob/f9282c0f03d049e0f13670afa2cf8a87f8ddf0cc/osquery/tables/networking/linux/process_open_sockets.cpp
// 在 osquery issue 1094 中(https://github.com/osquery/osquery/issues/1094) 解释了为什么剔除了用 netlink 获取的方式
// 大致为 netlink 的方式在 CentOS/RHEL6 不稳定, 经常会 fallback
// 可以看到之前 readnetlink 他们也有出现 timeout 的情况 https://github.com/osquery/osquery/pull/543
// 其他相关 issue: https://github.com/osquery/osquery/issues/671
// In Elkeid, socket rebuild again for better performance. By the way, since there is no race condition
// of netlink function execution, no netlink socket singleton or lock is needed.
// The source code is from: https://github.com/vishvananda/netlink/blob/main/socket_linux.go

const (
	sizeofSocketID      = 0x30
	sizeofSocketRequest = sizeofSocketID + 0x8
	sizeofSocket        = sizeofSocketID + 0x18
	netlinkLimit        = 1000
)

var (
	native       = nl.NativeEndian()
	networkOrder = binary.BigEndian
)

// pre-definition
type SocketID struct {
	SourcePort      uint16
	DestinationPort uint16
	Source          net.IP
	Destination     net.IP
	Interface       uint32
	Cookie          [2]uint32
}

// Socket represents a netlink socket.
type Socket struct {
	Family  uint8
	State   uint8
	Timer   uint8
	Retrans uint8
	ID      SocketID
	Expires uint32
	RQueue  uint32
	WQueue  uint32
	UID     uint32
	INode   uint32
}

func (s *Socket) deserialize(b []byte) error {
	if len(b) < sizeofSocket {
		return fmt.Errorf("socket data short read (%d); want %d", len(b), sizeofSocket)
	}
	rb := readBuffer{Bytes: b}
	s.Family = rb.Read()
	s.State = rb.Read()
	s.Timer = rb.Read()
	s.Retrans = rb.Read()
	s.ID.SourcePort = networkOrder.Uint16(rb.Next(2))
	s.ID.DestinationPort = networkOrder.Uint16(rb.Next(2))
	if s.Family == unix.AF_INET6 {
		s.ID.Source = net.IP(rb.Next(16))
		s.ID.Destination = net.IP(rb.Next(16))
	} else {
		s.ID.Source = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
		s.ID.Destination = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
	}
	s.ID.Interface = native.Uint32(rb.Next(4))
	s.ID.Cookie[0] = native.Uint32(rb.Next(4))
	s.ID.Cookie[1] = native.Uint32(rb.Next(4))
	s.Expires = native.Uint32(rb.Next(4))
	s.RQueue = native.Uint32(rb.Next(4))
	s.WQueue = native.Uint32(rb.Next(4))
	s.UID = native.Uint32(rb.Next(4))
	s.INode = native.Uint32(rb.Next(4))
	return nil
}

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
type SocketData struct {
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
	ID       SocketID
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

const (
	INET_DIAG_NONE = iota
	INET_DIAG_MEMINFO
	INET_DIAG_INFO
	INET_DIAG_VEGASINFO
	INET_DIAG_CONG
	INET_DIAG_TOS
	INET_DIAG_TCLASS
	INET_DIAG_SKMEMINFO
	INET_DIAG_SHUTDOWN
	INET_DIAG_DCTCPINFO
	INET_DIAG_PROTOCOL
	INET_DIAG_SKV6ONLY
	INET_DIAG_LOCALS
	INET_DIAG_PEERS
	INET_DIAG_PAD
	INET_DIAG_MARK
	INET_DIAG_BBRINFO
	INET_DIAG_CLASS_ID
	INET_DIAG_MD5SIG
	INET_DIAG_MAX
)

// Add limitation of socket, in case too much of this.
func parseNetlink(family, protocol uint8) (sockets []SocketData, err error) {
	var (
		s     *nl.NetlinkSocket
		req   *nl.NetlinkRequest
		state uint32
	)

	if s, err = nl.Subscribe(unix.NETLINK_INET_DIAG); err != nil {
		return
	}
	defer s.Close()

	req = nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	if protocol == unix.IPPROTO_UDP {
		state = 7
	} else if protocol == unix.IPPROTO_TCP {
		state = 10
	} else {
		err = fmt.Errorf("unsupported protocol %d", protocol)
		return
	}
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
			sockInfo := &Socket{}
			if err := sockInfo.deserialize(m.Data); err != nil {
				continue
			}
			socket := SocketData{
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
			socket.Username = cache.DefaultUserCache.GetUser(socket.UID).Username
			sockets = append(sockets, socket)
		}
	}
	return
}

// --- line ---

var (
	nlSocketContext     *network.Context
	nlSocketSingleton   *network.VNetlink
	nlSocketContextOnce sync.Once
	nlSocketOnce        sync.Once
)

func GetNlSocketContext() *network.Context {
	nlSocketContextOnce.Do(func() {
		nlSocketContext = &network.Context{}
	})
	return nlSocketContext
}

func GetNlSocketSingleton() *network.VNetlink {
	nlSocketOnce.Do(func() {
		nlSocketSingleton = &network.VNetlink{}
	})
	return nlSocketSingleton
}

// netlink 方式获取
func GetSockets(disableProc bool, status uint8) (sockets []network.Socket, err error) {
	var udpSockets, udp6Sockets, tcpSockets, tcp6Sockets []network.Socket
	ctx := GetNlSocketContext()
	nlsocket := GetNlSocketSingleton()
	// 先初始化协议
	nlsocket.Protocal = unix.NETLINK_INET_DIAG
	if err = ctx.IRetry(nlsocket); err != nil {
		return
	}

	if status != network.TCP_ESTABLISHED {
		if udpSockets, err = nlsocket.GetSockets(unix.AF_INET, unix.IPPROTO_UDP, status); err != nil {
			return
		}
		sockets = append(sockets, udpSockets...)
		udp6Sockets, err = nlsocket.GetSockets(unix.AF_INET6, unix.IPPROTO_UDP, status)
		if err == nil {
			sockets = append(sockets, udp6Sockets...)
		}
	}

	tcpSockets, err = nlsocket.GetSockets(unix.AF_INET, unix.IPPROTO_TCP, status)
	if err == nil {
		sockets = append(sockets, tcpSockets...)
	}
	tcp6Sockets, err = nlsocket.GetSockets(unix.AF_INET6, unix.IPPROTO_TCP, status)
	if err == nil {
		sockets = append(sockets, tcp6Sockets...)
	}

	inodeMap := make(map[uint32]int)
	for index, socket := range sockets {
		if socket.Inode != 0 {
			inodeMap[socket.Inode] = index
		}
	}
	if !disableProc {
		procs, err := procfs.AllProcs()
		if err == nil {
			for _, p := range procs {
				fds, _ := p.FileDescriptorTargets()
				for _, fd := range fds {
					if strings.HasPrefix(fd, "socket:[") {
						inode, _ := strconv.ParseUint(strings.TrimRight(fd[8:], "]"), 10, 32)
						index, ok := inodeMap[uint32(inode)]
						if ok {
							sockets[index].PID = int32(p.PID)
							sockets[index].Comm, _ = p.Comm()
							argv, err := p.CmdLine()
							if err == nil {
								if len(argv) > 16 {
									argv = argv[:16]
								}
								sockets[index].Argv = strings.Join(argv, " ")
								if len(sockets[index].Argv) > 32 {
									sockets[index].Argv = sockets[index].Argv[:32]
								}
							}
						}
					}
				}
			}
		}
	}
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

// 在同一时间突然流量激增导致丢弃，给一个初始随机值，再reset掉
func SocketJob(ctx context.Context) {
	init := true
	ticker := time.NewTicker(time.Second * time.Duration(rand.Intn(600)+1))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if init {
				ticker.Reset(30 * time.Minute)
				init = false
			}
			// 是否开启proc，统一关闭先
			if socks, err := GetSockets(false, network.TCP_ESTABLISHED); err == nil {
				if data, err := json.Marshal(socks); err == nil {
					rawdata := make(map[string]string)
					rawdata["data"] = string(data)
					rec := &plugin.Record{
						DataType:  1001,
						Timestamp: time.Now().Unix(),
						Data: &plugin.Payload{
							Fields: rawdata,
						},
					}
					share.Client.SendRecord(rec)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
