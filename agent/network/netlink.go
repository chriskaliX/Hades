package network

// 自实现的 netlink
import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"syscall"
)

const (
	CN_IDX_PROC = 0x1
	CN_VAL_PROC = 0x1

	PROC_CN_GET_FEATURES = 0
	PROC_CN_MCAST_LISTEN = 1
	PROC_CN_MCAST_IGNORE = 2

	PROC_EVENT_NONE     = 0x00000000
	PROC_EVENT_FORK     = 0x00000001
	PROC_EVENT_EXEC     = 0x00000002
	PROC_EVENT_UID      = 0x00000004
	PROC_EVENT_GID      = 0x00000040
	PROC_EVENT_SID      = 0x00000080
	PROC_EVENT_PTRACE   = 0x00000100
	PROC_EVENT_COMM     = 0x00000200
	PROC_EVENT_NS       = 0x00000400
	PROC_EVENT_COREDUMP = 0x40000000
	PROC_EVENT_EXIT     = 0x80000000
)

var (
	BYTE_ORDER = binary.LittleEndian
)

type cnMsg struct {
	Id    cbId
	Seq   uint32
	Ack   uint32
	Len   uint16
	Flags uint16
}

// linux/connector.h: struct cb_id
type cbId struct {
	Idx uint32
	Val uint32
}

// standard netlink header + connector header
type netlinkProcMessage struct {
	Header syscall.NlMsghdr
	Data   cnMsg
}

type Netlink struct {
	addr *syscall.SockaddrNetlink // Netlink socket address
	sock int                      // The syscall.Socket() file descriptor
	seq  uint32                   // struct cn_msg.seq
}

func (nl *Netlink) Connect() error {
	if err := nl.bind(); err != nil {
		return err
	}
	return nil
}

func (nl *Netlink) Init() error {
	return nil
}

func (nl *Netlink) String() string {
	return "netlink"
}

func (nl *Netlink) GetMaxRetry() uint {
	return 2
}

func (nl *Netlink) GetHashMod() uint {
	return 1
}

func (nl *Netlink) Close() {

}

func (nl *Netlink) GetStatus() bool {
	if nl.addr != nil {
		return true
	}
	return false
}

func (netlink *Netlink) bind() error {
	sock, err := syscall.Socket(
		syscall.AF_NETLINK,
		syscall.SOCK_DGRAM,
		syscall.NETLINK_CONNECTOR)

	if err != nil {
		return err
	}
	netlink.sock = sock
	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: CN_IDX_PROC,
	}
	netlink.addr = addr
	if err = syscall.Bind(netlink.sock, netlink.addr); err != nil {
		syscall.Close(netlink.sock)
		return err
	}
	return nil
}

func (netlink *Netlink) send(op uint32) error {
	netlink.seq++

	pr := &netlinkProcMessage{}
	plen := binary.Size(pr.Data) + binary.Size(op)
	pr.Header.Len = syscall.NLMSG_HDRLEN + uint32(plen)
	pr.Header.Type = uint16(syscall.NLMSG_DONE)
	pr.Header.Flags = 0
	pr.Header.Seq = netlink.seq
	pr.Header.Pid = uint32(os.Getpid())
	pr.Data.Id.Idx = CN_IDX_PROC
	pr.Data.Id.Val = CN_VAL_PROC
	pr.Data.Len = uint16(binary.Size(op))

	buf := bytes.NewBuffer(make([]byte, 0, pr.Header.Len))
	binary.Write(buf, BYTE_ORDER, pr)
	binary.Write(buf, BYTE_ORDER, op)

	err := syscall.Sendto(netlink.sock, buf.Bytes(), 0, netlink.addr)
	return err
}

// 开始监听 cn_proc
func (netlink *Netlink) StartCN() error {
	if netlink == nil {
		return errors.New("netlink is nil")
	}
	return netlink.send(PROC_CN_MCAST_LISTEN)
}

// netlink : 关闭 netlink 监听, 发送 IGNORE 指令, 并且关闭对应 Listen 的 socket
func (netlink *Netlink) StopCN() error {
	if netlink == nil {
		return errors.New("netlink is nil")
	}
	if err := netlink.send(PROC_CN_MCAST_IGNORE); err != nil {
		return err
	}
	return syscall.Close(netlink.sock)
}

// netlink : 跳过错误信息
// 接收回调 callback 来处理
func (netlink *Netlink) Receive(HandleFunc func([]byte)) {
	buf := make([]byte, syscall.Getpagesize())
	for {
		nr, _, err := syscall.Recvfrom(netlink.sock, buf, 0)
		if err != nil {
			continue
		}
		if nr < syscall.NLMSG_HDRLEN {
			continue
		}
		msgs, _ := syscall.ParseNetlinkMessage(buf[:nr])
		for _, m := range msgs {
			if m.Header.Type == syscall.NLMSG_DONE {
				HandleFunc(m.Data)
			}
		}
	}
}
