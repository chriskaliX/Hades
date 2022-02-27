package main

import (
	"bytes"
	"collector/cache"
	"collector/network"
	"collector/share"
	"encoding/binary"
	"sync"
	"syscall"
	"time"

	"github.com/chriskaliX/plugin"
	"go.uber.org/zap"
)

var (
	netlinkContext *network.Context
	netlink        *network.Netlink
)

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

// exit 事件
type ProcEventExit struct {
	ProcessPid  uint32
	ProcessTgid uint32
	ExitCode    uint32
	ExitSignal  uint32
}

// ptrace
type ProcEventPtrace struct {
	ProcessPid  int32
	ProcessTgid int32
	TracerPid   int32
	TracerTgid  int32
}

var (
	ProcEventForkPool   *sync.Pool
	ProcEventExecPool   *sync.Pool
	ProcEventPtracePool *sync.Pool
	procEventHeaderPool *sync.Pool
	cnMsgPool           *sync.Pool
	bufPool             *sync.Pool
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

	// cnMsg 对象池
	cnMsgPool = &sync.Pool{
		New: func() interface{} {
			return new(cnMsg)
		},
	}

	// 事件头对象池
	procEventHeaderPool = &sync.Pool{
		New: func() interface{} {
			return new(procEventHeader)
		},
	}

	// ptrace 对象池
	ProcEventPtracePool = &sync.Pool{
		New: func() interface{} {
			return new(ProcEventPtrace)
		},
	}

	bufPool = &sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}
}

func handleProcEvent(data []byte) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf = bytes.NewBuffer(data)

	msg := cnMsgPool.Get().(*cnMsg)
	binary.Read(buf, network.BYTE_ORDER, msg)

	hdr := procEventHeaderPool.Get().(*procEventHeader)
	binary.Read(buf, network.BYTE_ORDER, hdr)

	defer func() {
		bufPool.Put(buf)
		cnMsgPool.Put(msg)
		procEventHeaderPool.Put(hdr)
	}()

	// 关注 fork, exec,
	switch hdr.What {
	case network.PROC_EVENT_NONE:
	case network.PROC_EVENT_FORK:
		event := ProcEventForkPool.Get().(*ProcEventFork)
		defer ProcEventForkPool.Put(event)
		binary.Read(buf, network.BYTE_ORDER, event)
		// 进程树补充
		share.ProcessCache.Add(event.ChildPid, event.ParentPid)
	case network.PROC_EVENT_EXEC:
		// 对象池获取
		event := ProcEventExecPool.Get().(*ProcEventExec)
		defer ProcEventExecPool.Put(event)
		binary.Read(buf, network.BYTE_ORDER, event)
		pid := event.ProcessPid

		process, err := GetProcessInfo(int(pid))
		process.Source = "netlink"
		process.TID = int(event.ProcessTgid)
		if err != nil {
			cache.DefaultProcessPool.Put(process)
			return
		}
		// 白名单校验
		if share.WhiteListCheck(*process) {
			cache.DefaultProcessPool.Put(process)
			return
		}
		share.ProcessCmdlineCache.Add(pid, process.Exe)
		if ppid, ok := share.ProcessCache.Get(pid); ok {
			process.PPID = int(ppid.(uint32))
		}
		process.PidTree = share.GetPstree(uint32(process.PID))
		data, err := share.Marshal(process)

		// map 对象池
		if err == nil {
			rawdata := make(map[string]string)
			rawdata["data"] = string(data)
			rec := &plugin.Record{
				DataType:  1000,
				Timestamp: time.Now().Unix(),
				Data: &plugin.Payload{
					Fields: rawdata,
				},
			}
			share.Client.SendRecord(rec)
		}
		cache.DefaultProcessPool.Put(process)
	// 考虑获取 exit 事件, 用来捕获退出后从 LRU 里面剔除, 减小内存占用
	// 但是会让 LRU 里面的增多,
	case network.PROC_EVENT_EXIT:
	case network.PROC_EVENT_UID:
	case network.PROC_EVENT_GID:
	case network.PROC_EVENT_SID:
	// ptrace 事件监听
	// TODO:
	case network.PROC_EVENT_PTRACE:
	case network.PROC_EVENT_COMM:
	case network.PROC_EVENT_COREDUMP:
	default:
	}
}

func cn_proc_start() error {
	var err error
	netlinkContext = &network.Context{}
	netlink = &network.Netlink{}

	if err = netlinkContext.IRetry(netlink); err != nil {
		return err
	}
	if err = netlink.StartCN(); err != nil {
		zap.S().Error(err)
		return err
	}
	go netlink.Receive()
	go netlink.Handle(handleProcEvent)
	return nil
}
