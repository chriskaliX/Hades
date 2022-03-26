package network

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"

	"sync/atomic"

	"golang.org/x/sys/unix"
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

var (
	_bytePool *sync.Pool
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
	sock int32                    // The syscall.Socket() file descriptor
	seq  uint32                   // struct cn_msg.seq; TODO?
}

func (nl *Netlink) Connect() error {
	sock, err := unix.Socket(
		syscall.AF_NETLINK,
		syscall.SOCK_DGRAM,
		syscall.NETLINK_CONNECTOR)
	if err != nil {
		return err
	}
	nl.sock = int32(sock)
	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: CN_IDX_PROC,
	}
	nl.addr = addr
	if err = syscall.Bind(nl.Getfd(), nl.addr); err != nil {
		syscall.Close(nl.Getfd())
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
	return 3
}

func (nl *Netlink) GetHashMod() uint {
	return 1
}

// maybe error?
func (nl *Netlink) Close() {
	if nl == nil {
		return
	}
	syscall.Close(nl.Getfd())
}

func (nl *Netlink) Getfd() int {
	return int(atomic.LoadInt32(&nl.sock))
}

func (nl *Netlink) send(op uint32) error {
	nl.seq++
	pr := &netlinkProcMessage{}
	plen := binary.Size(pr.Data) + binary.Size(op)
	pr.Header.Len = syscall.NLMSG_HDRLEN + uint32(plen)
	pr.Header.Type = uint16(syscall.NLMSG_DONE)
	pr.Header.Flags = 0
	pr.Header.Seq = nl.seq
	pr.Header.Pid = uint32(os.Getpid())
	pr.Data.Id.Idx = CN_IDX_PROC
	pr.Data.Id.Val = CN_VAL_PROC
	pr.Data.Len = uint16(binary.Size(op))
	buf := bytes.NewBuffer(make([]byte, 0, pr.Header.Len))
	binary.Write(buf, BYTE_ORDER, pr)
	binary.Write(buf, BYTE_ORDER, op)
	err := syscall.Sendto(nl.Getfd(), buf.Bytes(), 0, nl.addr)
	return err
}

// 开始监听 cn_proc
func (nl *Netlink) StartCN() error {
	if nl == nil {
		return errors.New("netlink is nil")
	}
	return nl.send(PROC_CN_MCAST_LISTEN)
}

var MsgChannel = make(chan []byte, 512)

/*
	2021-11-06 TODO: 回想了一下, drop 操作是不是应该在这里
	压测了一下还是没有解决高占用的问题, 因为 syscall 不会降低的
	之前理解有误, 应该在这里做丢弃动作
	转换成队列, 超过丢弃, 参考美团的文章内容
	内核返回数据太快，用户态ParseNetlinkMessage解析读取太慢，
	导致用户态网络Buff占满，内核不再发送数据给用户态，进程空闲。
	对于这个问题，我们在用户态做了队列控制
	看一下具体的sock满了的问题, 因为 Recvfrom 还是会导致高占用
	同样的, 因为异步且限制了消费速度, 导致瞬时丢的概率非常大。能想到的就是做加速,
	观察一下大部分都是 exit, 可以不消费完整的 msg 而优先判断 header 增快速度
	TODO: 看一下上述方案的可行性
*/
func (nl *Netlink) Receive() {
	buf := _bytePool.Get().([]byte)
	for {
		// 保证 Recvefrom 运行, 防止 netlink 堵塞
		// 但是 receive 还是很高? 需要继续看一下
		nr, _, err := unix.Recvfrom(nl.Getfd(), buf, 0)
		if err != nil {
			continue
		}
		if nr < syscall.NLMSG_HDRLEN {
			continue
		}
		select {
		case MsgChannel <- buf[:nr]:
		default:
			// drop here
		}
	}
}

// 频繁创建对象的全部用 sync.Pool
var (
	netlinkMessagePool *sync.Pool
)

func (netlink *Netlink) Handle(HandleFunc func([]byte)) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for msg := range MsgChannel {
		msgs := netlinkMessagePool.Get().([]syscall.NetlinkMessage)
		msgs, _ = syscall.ParseNetlinkMessage(msg)
		_bytePool.Put(msg)
		select {
		case <-ticker.C:
			for _, m := range msgs {
				if m.Header.Type == syscall.NLMSG_DONE {
					HandleFunc(m.Data)
				}
			}
		}
		netlinkMessagePool.Put(msgs)
	}
}

func init() {
	// 正常情况下长度为 1
	netlinkMessagePool = &sync.Pool{
		New: func() interface{} {
			return make([]syscall.NetlinkMessage, 1)
		},
	}
	pageSize := syscall.Getpagesize()
	_bytePool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, pageSize)
		},
	}
}
