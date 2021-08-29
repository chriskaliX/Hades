package connector

import (
	"bytes"
	"encoding/binary"
	"hids-agent/collector"
	"hids-agent/global"
	"hids-agent/network"
	"sync"
	"syscall"
)

var (
	netlinkContext   *network.Context
	netlinkSingleton *network.Netlink
	nlContextOnce    sync.Once
	nlOnce           sync.Once
)

// 获取netlink单例
func GetNlSingleton() *network.Netlink {
	nlOnce.Do(func() {
		netlinkSingleton = &network.Netlink{}
	})
	return netlinkSingleton
}

// 获取netlink单例
func GetNlContextSingleton() *network.Context {
	nlContextOnce.Do(func() {
		netlinkContext = &network.Context{}
	})
	return netlinkContext
}

// linux/cn_proc.h: struct proc_event.{what,cpu,timestamp_ns}
type procEventHeader struct {
	What      uint32
	Cpu       uint32
	Timestamp uint64
}

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

// linux/cn_proc.h: struct proc_event.fork
type ProcEventFork struct {
	ParentPid  uint32
	ParentTgid uint32
	ChildPid   uint32
	ChildTgid  uint32
}

// linux/cn_proc.h: struct proc_event.exec
type ProcEventExec struct {
	ProcessPid  uint32
	ProcessTgid uint32
}

type ProcEventExit struct {
	ProcessPid  uint32
	ProcessTgid uint32
	ExitCode    uint32
	ExitSignal  uint32
}

var (
	ProcEventForkPool   *sync.Pool
	ProcEventExecPool   *sync.Pool
	cnMsgPool           *sync.Pool
	procEventHeaderPool *sync.Pool
)

func init() {
	// 对象池初始化
	ProcEventForkPool = &sync.Pool{
		New: func() interface{} {
			return new(ProcEventFork)
		},
	}
	ProcEventExecPool = &sync.Pool{
		New: func() interface{} {
			return new(ProcEventExec)
		},
	}
	cnMsgPool = &sync.Pool{
		New: func() interface{} {
			return new(cnMsg)
		},
	}
	procEventHeaderPool = &sync.Pool{
		New: func() interface{} {
			return new(procEventHeader)
		},
	}
}

func handleProcEvent(data []byte) {
	buf := bytes.NewBuffer(data)
	msg := cnMsgPool.Get().(*cnMsg)
	defer cnMsgPool.Put(msg)
	hdr := procEventHeaderPool.Get().(*procEventHeader)
	defer procEventHeaderPool.Put(hdr)
	binary.Read(buf, network.BYTE_ORDER, msg)
	binary.Read(buf, network.BYTE_ORDER, hdr)
	// 重点关注 Fork & Exec
	switch hdr.What {
	case network.PROC_EVENT_NONE:
	// fork 事件
	case network.PROC_EVENT_FORK:
		event := ProcEventForkPool.Get().(*ProcEventFork)
		defer ProcEventForkPool.Put(event)
		binary.Read(buf, network.BYTE_ORDER, event)
		// fork 将事件刷入进程树
		global.ProcessCache.Add(event.ChildPid, event.ParentPid)
	// exec 事件
	case network.PROC_EVENT_EXEC:
		// 对象池获取
		event := ProcEventExecPool.Get().(*ProcEventExec)
		defer ProcEventExecPool.Put(event)
		kafkaLog := network.KafkaLogPool.Get().(*network.KafkaLog)
		// 读取exec
		binary.Read(buf, network.BYTE_ORDER, event)
		pid := event.ProcessPid
		kafkaLog.Process, _ = collector.GetProcessInfo(pid)
		global.ProcessCmdlineCache.Add(pid, kafkaLog.Process.Cmdline)
		if ppid, ok := global.ProcessCache.Get(pid); ok {
			kafkaLog.PPID = int(ppid.(uint32))
		}
		kafkaLog.Pstree = global.GetPstree(pid)
		network.KafkaChannel <- kafkaLog
	case network.PROC_EVENT_NS:
	case network.PROC_EVENT_EXIT:
	case network.PROC_EVENT_UID:
	case network.PROC_EVENT_GID:
	case network.PROC_EVENT_SID:
	case network.PROC_EVENT_PTRACE:
	case network.PROC_EVENT_COMM:
	case network.PROC_EVENT_COREDUMP:
	default:
	}
}

func CN_PROC_START() error {
	var err error
	nlSingleton := GetNlSingleton()
	contextInstance := GetNlContextSingleton()
	if err = contextInstance.IRetry(nlSingleton); err != nil {
		return err
	}
	if err = nlSingleton.StartCN(); err != nil {
		return err
	}
	go nlSingleton.Receive(handleProcEvent)
	return nil
}
