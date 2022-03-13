package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/user"
	"strconv"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

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

type VNetlink struct {
	socket *nl.NetlinkSocket
	// 关闭信号
	shutdown bool
	// 获取类型, 目前是 unix.NETLINK_INET_DIAG 以及 CN_PROC
	Protocal int
}

func (netlink *VNetlink) Init() error {
	if netlink.Protocal <= 0 {
		return errors.New("protocal is not supported")
	}
	return nil
}

func (netlink *VNetlink) Connect() error {
	var err error
	// 协议的两种, 一个是CN_PROC, 一个获取 net
	// unix.NETLINK_INET_DIAG
	// PROC_CN_MCAST_LISTEN
	if netlink.socket, err = nl.Subscribe(netlink.Protocal); err != nil {
		return err
	}
	return nil
}

func (netlink *VNetlink) String() string {
	return "vnetlink"
}

func (netlink *VNetlink) GetMaxRetry() uint {
	return 3
}

func (netlink *VNetlink) GetHashMod() uint {
	return 1
}

func (netlink *VNetlink) Close() {
	netlink.shutdown = true
}

// 发送 socket
// state 代表状态, 10 是监听的
const (
	LISTEN          = 0
	TCP_ESTABLISHED = 1
)

func (netlink *VNetlink) GetSockets(family, protocol uint8, status uint8) (sockets []Socket, err error) {
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	var state uint32
	if protocol == unix.IPPROTO_UDP {
		state = 7
	} else if protocol == unix.IPPROTO_TCP {
		if status == TCP_ESTABLISHED {
			state = 1
		} else if status == LISTEN {
			state = 10
		} else {
			err = fmt.Errorf("unsupported status %d", protocol)
			return
		}
	} else {
		err = fmt.Errorf("unsupported protocol %d", protocol)
		return
	}
	req.AddData(&socketRequest{
		family:   family,
		protocol: protocol,
		ext:      (1 << (INET_DIAG_VEGASINFO - 1)) | (1 << (INET_DIAG_INFO - 1)),
		states:   uint32(1 << state),
	})
	if err = netlink.socket.Send(req); err != nil {
		return
	}
loop:
	for {
		if netlink.shutdown {
			err = errors.New("shutdown is true")
			return
		}

		msgs, from, err := netlink.socket.Receive()
		if err != nil {
			return nil, err
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
				continue
			}
			sockInfo := &_socket{}
			if err := sockInfo.deserialize(m.Data); err != nil {
				continue
			}
			socket := Socket{
				SIP:       sockInfo.id.source,
				DIP:       sockInfo.id.destination,
				SPort:     sockInfo.id.sourcePort,
				DPort:     sockInfo.id.destinationPort,
				UID:       sockInfo.uid,
				Interface: sockInfo.id._interface,
				Family:    sockInfo.family,
				State:     sockInfo.state,
				Inode:     sockInfo.inode,
				Type:      protocol,
			}
			if user, err := user.LookupId(strconv.Itoa(int(sockInfo.uid))); err == nil {
				socket.Username = user.Name
			}
			sockets = append(sockets, socket)
		}
	}
	return
}

// 发送 cn_proc
func (netlink *VNetlink) StartCN() error {
	req := nl.NewNetlinkRequest(PROC_CN_MCAST_LISTEN, 0)
	if netlink.socket == nil {
		return errors.New("netlink is nil")
	}
	if err := netlink.socket.Send(req); err != nil {
		return err
	}
	return nil
}

func (netlink *VNetlink) StopCN() error {
	if netlink.socket == nil {
		return errors.New("netlink is nil")
	}
	req := nl.NewNetlinkRequest(PROC_CN_MCAST_IGNORE, 0)
	if err := netlink.socket.Send(req); err != nil {
		return err
	}
	return nil
}

func (netlink *VNetlink) ReceiveCN(HandleFunc func([]byte)) {
	for {
		if netlink.shutdown {
			// 这里有问题
			netlink.StopCN()
			return
		}

		msgs, from, err := netlink.socket.Receive()
		if err != nil {
			continue
		}
		if from.Pid != nl.PidKernel {
			continue
		}
		if len(msgs) == 0 {
			continue
		}
		for _, m := range msgs {
			if m.Header.Type == syscall.NLMSG_DONE {
				HandleFunc(m.Data)
			}
		}
	}
}

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
	PID       int32  `json:"pid"`
	Argv      string `json:"argv"`
	Comm      string `json:"comm"`
	Type      uint8  `json:"type"`
}

// SocketID identifies a single socket.
type _socketID struct {
	sourcePort      uint16
	destinationPort uint16
	source          net.IP
	destination     net.IP
	_interface      uint32
	cookie          [2]uint32
}

// Socket represents a netlink socket.
type _socket struct {
	family  uint8
	state   uint8
	timer   uint8
	retrans uint8
	id      _socketID
	expires uint32
	rQueue  uint32
	wQueue  uint32
	uid     uint32
	inode   uint32
}

const (
	sizeofSocketID      = 0x30
	sizeofSocketRequest = sizeofSocketID + 0x8
	sizeofSocket        = sizeofSocketID + 0x18
)

var (
	native       = nl.NativeEndian()
	networkOrder = binary.BigEndian
)

type socketRequest struct {
	family   uint8
	protocol uint8
	ext      uint8
	pad      uint8
	states   uint32
	id       _socketID
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
	b.Write(r.family)
	b.Write(r.protocol)
	b.Write(r.ext)
	b.Write(r.pad)
	native.PutUint32(b.Next(4), r.states)
	networkOrder.PutUint16(b.Next(2), r.id.sourcePort)
	networkOrder.PutUint16(b.Next(2), r.id.destinationPort)
	if r.family == unix.AF_INET6 {
		copy(b.Next(16), r.id.source)
		copy(b.Next(16), r.id.destination)
	} else {
		copy(b.Next(4), r.id.source.To4())
		b.Next(12)
		copy(b.Next(4), r.id.destination.To4())
		b.Next(12)
	}
	native.PutUint32(b.Next(4), r.id._interface)
	native.PutUint32(b.Next(4), r.id.cookie[0])
	native.PutUint32(b.Next(4), r.id.cookie[1])
	return b.Bytes
}

func (r *socketRequest) Len() int { return sizeofSocketRequest }

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

func (s *_socket) deserialize(b []byte) error {
	if len(b) < sizeofSocket {
		return fmt.Errorf("socket data short read (%d); want %d", len(b), sizeofSocket)
	}
	rb := readBuffer{Bytes: b}
	s.family = rb.Read()
	s.state = rb.Read()
	s.timer = rb.Read()
	s.retrans = rb.Read()
	s.id.sourcePort = networkOrder.Uint16(rb.Next(2))
	s.id.destinationPort = networkOrder.Uint16(rb.Next(2))
	if s.family == unix.AF_INET6 {
		s.id.source = net.IP(rb.Next(16))
		s.id.destination = net.IP(rb.Next(16))
	} else {
		s.id.source = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
		s.id.destination = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
	}
	s.id._interface = native.Uint32(rb.Next(4))
	s.id.cookie[0] = native.Uint32(rb.Next(4))
	s.id.cookie[1] = native.Uint32(rb.Next(4))
	s.expires = native.Uint32(rb.Next(4))
	s.rQueue = native.Uint32(rb.Next(4))
	s.wQueue = native.Uint32(rb.Next(4))
	s.uid = native.Uint32(rb.Next(4))
	s.inode = native.Uint32(rb.Next(4))
	return nil
}
