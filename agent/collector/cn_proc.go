package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"strconv"
	"sync"
	"syscall"
	"time"

	"agent/config"
	"agent/global"
	"agent/global/structs"
	"agent/network"
	"agent/utils"
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
	case network.PROC_EVENT_FORK:
		event := ProcEventForkPool.Get().(*ProcEventFork)
		defer ProcEventForkPool.Put(event)
		binary.Read(buf, network.BYTE_ORDER, event)
		// 进程树补充
		global.ProcessCache.Add(event.ChildPid, event.ParentPid)
	case network.PROC_EVENT_EXEC:
		// 对象池获取
		event := ProcEventExecPool.Get().(*ProcEventExec)
		defer ProcEventExecPool.Put(event)
		binary.Read(buf, network.BYTE_ORDER, event)
		pid := event.ProcessPid
		/*
			转换成队列, 超过丢弃, 参考美团的文章内容
			内核返回数据太快，用户态ParseNetlinkMessage解析读取太慢，
			导致用户态网络Buff占满，内核不再发送数据给用户态，进程空闲。
			对于这个问题，我们在用户态做了队列控制

			采用 PidChannel 作为缓冲池, 完全读取或者丢弃 pid,
			防止 netlink 阻塞, 控制 fd 打开频率, 防止瞬时打开多个
		*/
		select {
		case global.PidChannel <- pid:
		default:
			// drop here
		}
	case network.PROC_EVENT_NS:
	case network.PROC_EVENT_EXIT:
	case network.PROC_EVENT_UID:
	case network.PROC_EVENT_GID:
	case network.PROC_EVENT_SID:

	// ptrace 事件监听
	// todo:
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
		return err
	}
	go netlink.Receive(handleProcEvent)
	return nil
}

// 开启定期消费
// 控制消费速率, 多余的事件会被丢弃。之前读取为一毫秒一次, 导致 CPU 最高占用过 40%
// 目前控制后, 最高 10% 左右, 速率控制问题
// 防止打开过多 fd 造成资源占用问题
func NetlinkCNProcJob(ctx context.Context) {
	if err := cn_proc_start(); err != nil {
		return
	}
	ticker := time.NewTicker(time.Millisecond * 4)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pid := <-global.PidChannel
			process, err := GetProcessInfo(pid)
			if err != nil {
				process.Reset()
				structs.ProcessPool.Put(process)
				continue
			}
			// 白名单校验
			if config.WhiteListCheck(process) {
				process.Reset()
				structs.ProcessPool.Put(process)
				continue
			}

			global.ProcessCmdlineCache.Add(pid, process.Cmdline)
			if ppid, ok := global.ProcessCache.Get(pid); ok {
				process.PPID = int(ppid.(uint32))
			}
			process.PidTree = global.GetPstree(uint32(process.PID))
			// json 对 html 字符会转义, 转用下面方法是否会对性能有影响? 需要再看一下
			data, err := utils.Marshal(process)
			if err == nil {
				rawdata := make(map[string]string)
				rawdata["data"] = string(data)
				rawdata["time"] = strconv.Itoa(int(global.Time))
				rawdata["data_type"] = "1000"
				global.UploadChannel <- rawdata
			}
			process.Reset()
			structs.ProcessPool.Put(process)
		case <-ctx.Done():
			return
		}
	}
}
