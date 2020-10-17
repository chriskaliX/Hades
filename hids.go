/*
	代码来源:https://github.com/kinvolk/nswatch/blob/5ed779a0cbdfa80403ea42909ca157a89719f159/nswatch.go
	netlink原理学习:
		参考文章:https://www.cnblogs.com/LittleHann/p/4418754.html
		没有学过linux内核编程，没有深度了解过，纯属为了初步了解 HIDS 进行学习和改进

		本次学习是通过 netlink connector 进行用户态 <-> 内核态的交互。
		相比于auditd来说，netlink connector对系统没有入侵性（其实auditd好像也不多）。但是获取到的数据较少，仅有pid，
		再从pid去获取到更多信息（如这里获取cmd）。auditd可以获取到更多信息，但是依赖环境
*/

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"io/ioutil"
	"time"
	"strconv"
)

var fdch chan int

func init() {
	fdch = make(chan int, 10000)
}


const (
	// <linux/connector.h>
	CN_IDX_PROC = 0x1
	CN_VAL_PROC = 0x1

	// <linux/cn_proc.h>
	PROC_CN_GET_FEATURES = 0
	PROC_CN_MCAST_LISTEN = 1
	PROC_CN_MCAST_IGNORE = 2

	/*
		这个应该是获取对应的状态号的
	*/
	PROC_EVENT_NONE   = 0x00000000
	PROC_EVENT_FORK   = 0x00000001
	PROC_EVENT_EXEC   = 0x00000002
	PROC_EVENT_UID    = 0x00000004
	PROC_EVENT_GID    = 0x00000040
	PROC_EVENT_SID    = 0x00000080
	PROC_EVENT_PTRACE = 0x00000100
	PROC_EVENT_COMM   = 0x00000200
	PROC_EVENT_NS     = 0x00000400
	/* "next" should be 0x00000800 */
	/* "last" is the last process event: exit,
	* while "next to last" is coredumping event */
	PROC_EVENT_COREDUMP = 0x40000000
	PROC_EVENT_EXIT     = 0x80000000
)

var (
	byteOrder = binary.LittleEndian
	seq uint32
)

// linux/connector.h: struct cb_id
type cbId struct {
	Idx uint32
	Val uint32
}

// linux/connector.h: struct cb_msg
/*
	发送的结构体定义
*/
type cnMsg struct {
	Id    cbId
	Seq   uint32
	Ack   uint32
	Len   uint16
	Flags uint16
}

// linux/cn_proc.h: struct proc_event.{what,cpu,timestamp_ns}
type procEventHeader struct {
	What      uint32
	Cpu       uint32
	Timestamp uint64
}

type namespaceEventHeader struct {
	Timestamp   uint64
	ProcessPid  uint32
	ProcessTgid uint32
	Reason      uint32
	Count       uint32
}

type namespaceEventContent struct {
	Type    uint32
	Flags   uint32
	OldInum uint64
	Inum    uint64
}

// linux/cn_proc.h: struct proc_event.fork
type forkProcEvent struct {
	ParentPid  uint32
	ParentTgid uint32
	ChildPid   uint32
	ChildTgid  uint32
}

// linux/cn_proc.h: struct proc_event.exec
type execProcEvent struct {
	ProcessPid  uint32
	ProcessTgid uint32
}

// linux/cn_proc.h: struct proc_event.exec
type nsProcItem struct {
	ItemType uint32
	Flag     uint32
	OldInum  uint64
	Inum     uint64
}
type nsProcEvent struct {
	ProcessPid  uint32
	ProcessTgid uint32
	Reason      uint32
	Count       uint32
	Items       [7]nsProcItem
}

// linux/cn_proc.h: struct proc_event.exit
type exitProcEvent struct {
	ProcessPid  uint32
	ProcessTgid uint32
	ExitCode    uint32
	ExitSignal  uint32
}

// standard netlink header + connector header
/*
	发向内核的请求数据包格式为 netlink消息头+数据
	https://www.cnblogs.com/big-xuyue/p/3440212.html
*/
type netlinkProcMessage struct {
	Header syscall.NlMsghdr
	Data   cnMsg
}

func subscribe(sock int, addr *syscall.SockaddrNetlink, op uint32) {
	seq++

	pr := &netlinkProcMessage{}
	plen := binary.Size(pr.Data) + binary.Size(op)

	//struct nlmsghdr
	//{
	//	__u32 nlmsg_len;   /* Length of message */
	//	__u16 nlmsg_type;  /* Message type*/
	//	__u16 nlmsg_flags; /* Additional flags */
	//	__u32 nlmsg_seq;   /* Sequence number */
	//	__u32 nlmsg_pid;   /* Sending process PID */
	//};	
	/*
		这个是C语言中的，golang的翻文档即可
		下面开始填充头
	*/
	pr.Header.Len = syscall.NLMSG_HDRLEN + uint32(plen)
	pr.Header.Type = uint16(syscall.NLMSG_DONE)
	pr.Header.Flags = 0
	pr.Header.Seq = seq
	pr.Header.Pid = uint32(os.Getpid())

	pr.Data.Id.Idx = CN_IDX_PROC
	pr.Data.Id.Val = CN_VAL_PROC

	pr.Data.Len = uint16(binary.Size(op))

	buf := bytes.NewBuffer(make([]byte, 0, pr.Header.Len))
	binary.Write(buf, byteOrder, pr)
	binary.Write(buf, byteOrder, op)

	err := syscall.Sendto(sock, buf.Bytes(), 0, addr)
	if err != nil {
		fmt.Printf("sendto failed: %v\n", err)
		os.Exit(1)
	}
}

/*
	从pid中读取数据，这里仅读取命令行作为展示
	有时候会出现读取的命令为空，原因是因为 -> 很多进程启动快速结束销毁，导致没来得及抓到
*/

func receive(sock int) {
	buf := make([]byte, syscall.Getpagesize())

	for {
		nr, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			fmt.Printf("recvfrom failed: %v\n", err)
			os.Exit(1)
		}
		if nr < syscall.NLMSG_HDRLEN {
			continue
		}

		msgs, _ := syscall.ParseNetlinkMessage(buf[:nr])
		for _, m := range msgs {
			if m.Header.Type == syscall.NLMSG_DONE {
				handleProcEvent(m.Data)
			}
		}
	}
}

func readProc(fd string) bool {
	var fdstr string
	f, err := os.Open("/proc/" + fd + "/cmdline")
	if err != nil {
		return false
	}
	defer f.Close()
	bytesf, err := ioutil.ReadAll(f)
	for _,v := range bytesf {
		if v == 0 {
			fdstr = fdstr + " "
		} else {
			fdstr = fdstr + string(v)
		}
	}
	if err != nil {
		return false
	}
	fmt.Println("\033[;32m[+]\033[0m : " + time.Now().Format("2006-01-02 15:04:05") + "[" + fd + "]" +"\t" + fdstr)
	return true
}

func getProc() {
	go func() {
		for {
			fd, ok := <- fdch
			if ok{
				status := readProc(strconv.Itoa(fd))
				if !status {
					fmt.Println("\033[;31m[-]\033[0m : " + time.Now().Format("2006-01-02 15:04:05") + "[" + strconv.Itoa(fd) + "]" + "\t" + "Read Failed")
				}
			}
		}
	}()
}

/*
	处理返回来的消息进程
*/
func handleProcEvent(data []byte) {
	buf := bytes.NewBuffer(data)
	msg := &cnMsg{}
	hdr := &procEventHeader{}

	binary.Read(buf, byteOrder, msg)
	binary.Read(buf, byteOrder, hdr)

	switch hdr.What {
	case PROC_EVENT_NONE:
		fmt.Printf("none: flags=%v\n", msg.Flags)

	case PROC_EVENT_FORK:
		// event := &forkProcEvent{}
		// binary.Read(buf, byteOrder, event)
		// ppid := int(event.ParentTgid)
		// pid := int(event.ChildTgid)

		// fmt.Printf("fork: ppid=%v pid=%v\n", ppid, pid)

	case PROC_EVENT_EXEC:
		event := &execProcEvent{}
		binary.Read(buf, byteOrder, event)
		pid := int(event.ProcessTgid)

		fdch <- pid
		fmt.Printf("exec: pid=%v\n", pid)

	case PROC_EVENT_NS:
		event := &nsProcEvent{}
		binary.Read(buf, byteOrder, event)
		pid := int(event.ProcessTgid)
		count := int(event.Count)
		reason := int(event.Reason)

		var reasonStr string
		switch reason {
		case 1:
			reasonStr = "clone"
		case 2:
			reasonStr = "setns"
		case 3:
			reasonStr = "unshare"
		default:
			reasonStr = "unknown"
		}

		fmt.Printf("ns: pid=%v reason=%v count=%v\n", pid, reasonStr, count)

		for i := 0; i < count; i++ {

			itemType := uint64(event.Items[i].ItemType)
			oldInum := uint64(event.Items[i].OldInum)
			inum := uint64(event.Items[i].Inum)

			var typeStr string
			switch itemType {
			case syscall.CLONE_NEWPID:
				typeStr = "pid "
			case syscall.CLONE_NEWNS:
				typeStr = "mnt "
			case syscall.CLONE_NEWNET:
				typeStr = "net "
			case syscall.CLONE_NEWUTS:
				typeStr = "uts "
			case syscall.CLONE_NEWIPC:
				typeStr = "ipc "
			case syscall.CLONE_NEWUSER:
				typeStr = "user"
			default:
				typeStr = "unknown"
			}

			fmt.Printf("    type=%s %v -> %v\n", typeStr, oldInum, inum)
		}

	case PROC_EVENT_EXIT:
		// event := &exitProcEvent{}
		// binary.Read(buf, byteOrder, event)
		// pid := int(event.ProcessTgid)

		// fmt.Printf("exit: pid=%v\n", pid)

	case PROC_EVENT_UID:
	case PROC_EVENT_GID:
	case PROC_EVENT_SID:
	case PROC_EVENT_PTRACE:
	case PROC_EVENT_COMM:
	case PROC_EVENT_COREDUMP:

	default:
		fmt.Printf("???: what=%x\n", hdr.What)
	}
}

func main() {
	/*
		FROM : https://www.icode9.com/content-3-720965.html	
		SOCK_RAW 和 SOCK_DGRAM 对于 netlink来说是一样的
		NETLINK_ROUTE:接收路由信息，更新链接信息，更新路由表，网络邻居，排队规则，拥塞等等
		NETLINK_SELINUX:linux事件通知
		NETLINK_AUDIT:审计模块，用于检测统计内核的操作，比如杀死进程，退出等。aditctl
		NETLINK_CONNECTOR:内核链接器5.2版本及以前
	*/
	getProc()

	// 创建 NETLINK_CONNECTOR 
	/*
	翻开家中珍藏的 "UNIX环境高级编程" 第16章 -> 网络IPC:套接字，找到socket开始学习，顺别记笔记
	int socket(int domain, int type, int protocol)
		domain:
			确定通信的特性，包括地址格式。各个域的开头经常以 AF_ 开头，意思为(Address Family)
			本次使用的是 AF_NETLINK 域.
		type:
			确定套接字的类型，进一步确定通信特征。
			SOCK_DGRAM		固定长度的、无连接的、不可靠的报文传递
			SOCK_RAW		IP协议的数据报接口
			...
		protocol:
			协议选择
	
	Golang的具体可以看官方文档
	*/
	sock, err := syscall.Socket(
		syscall.AF_NETLINK,
		syscall.SOCK_DGRAM,
		syscall.NETLINK_CONNECTOR)
	if err != nil {
		fmt.Printf("socket failed: %v\n", err)
		os.Exit(1)
	}

	/*
		type SockaddrNetlink struct {
			Family uint16
			Pad    uint16
			Pid    uint32
			Groups uint32
			// contains filtered or unexported fields
		}
		这里设置CN_IDX_PROC的原因和底层我暂时没找到，只有这个
		https://blog.csdn.net/Longyu_wlz/article/details/108940087
	*/
	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: CN_IDX_PROC,
	}

	err = syscall.Bind(sock, addr)
	if err != nil {
		fmt.Printf("bind failed: %v\n", err)
		os.Exit(1)
	}

	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "sub":
			subscribe(sock, addr, PROC_CN_MCAST_LISTEN)
		case "unsub":
			subscribe(sock, addr, PROC_CN_MCAST_IGNORE)
		case "features":
			subscribe(sock, addr, PROC_CN_GET_FEATURES)
		}
	}

	receive(sock)
}
