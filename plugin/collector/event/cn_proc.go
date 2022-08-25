package event

import (
	"collector/cache"
	"collector/share"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	plugin "github.com/chriskaliX/SDK/transport"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// TODO: simplify this and remove memory related field
var (
	DefaultNetlink = &Netlink{}
	ErrTooShort    = errors.New("buffer too short")
	ErrNothing     = errors.New("nothing")
)

const (
	CN_IDX_PROC          = 0x1
	CN_VAL_PROC          = 0x1
	PROC_CN_MCAST_LISTEN = 0x1
	PROC_EVENT_NONE      = 0x00000000
	PROC_EVENT_FORK      = 0x00000001
	PROC_EVENT_EXEC      = 0x00000002
	PROC_EVENT_UID       = 0x00000004
	PROC_EVENT_GID       = 0x00000040
	PROC_EVENT_SID       = 0x00000080
	PROC_EVENT_PTRACE    = 0x00000100
	PROC_EVENT_COMM      = 0x00000200
	PROC_EVENT_NS        = 0x00000400
	PROC_EVENT_COREDUMP  = 0x40000000
	PROC_EVENT_EXIT      = 0x80000000
	Netlink_DATATYPE     = 1000
)

var _ Event = (*Netlink)(nil)

type Netlink struct {
	// buffer and cursor
	buffer []byte
	cursor int
	sock   *nl.NetlinkSocket

	BasicEvent
}

func (n Netlink) DataType() int {
	return Netlink_DATATYPE
}

func (n Netlink) String() string {
	return "ncp"
}

func (n *Netlink) Init(name string) (err error) {
	var nlmsg nl.NetlinkRequest
	n.BasicEvent.Init(name)
	// just copy from old netlink
	// not good enough, code will be changed in future
	// follow the netlink lib, use the release (now it's pre-release)
	// https://github.com/vishvananda/netlink
	n.sock, err = nl.SubscribeAt(netns.None(), netns.None(), unix.NETLINK_CONNECTOR, CN_IDX_PROC)
	if err != nil {
		return err
	}
	nlmsg.Pid = uint32(os.Getpid())
	nlmsg.Type = unix.NLMSG_DONE
	nlmsg.Len = uint32(unix.SizeofNlMsghdr)
	cm := nl.NewCnMsg(CN_IDX_PROC, CN_VAL_PROC, PROC_CN_MCAST_LISTEN)
	nlmsg.AddData(cm)
	n.sock.Send(&nlmsg)
	return nil
}

// TODO: The speed control things in here
func (n *Netlink) RunSync(ctx context.Context) (err error) {
	var result string
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			msgs, from, err := n.sock.Receive()
			if err != nil {
				continue
			}
			if from.Pid != nl.PidKernel {
				continue
			}
			for _, msg := range msgs {
				if msg.Header.Type == syscall.NLMSG_DONE {
					if result, err = n.Handle(msg.Data); err != nil {
						continue
					}
					rawdata := make(map[string]string)
					if share.Env == "debug" {
						fmt.Println(result)
					}
					rawdata["data"] = string(result)
					rec := &plugin.Record{
						DataType:  Netlink_DATATYPE,
						Timestamp: time.Now().Unix(),
						Data: &plugin.Payload{
							Fields: rawdata,
						},
					}
					share.Client.SendRecord(rec)
				}
			}
		}
	}
}

func (n *Netlink) SetBuffer(_byte []byte) {
	n.buffer = append([]byte(nil), _byte...)
	n.cursor = 0
}

func (n *Netlink) DecodeMsg() (err error) {
	offset := n.cursor
	if len(n.buffer[offset:]) < 20 {
		err = ErrTooShort
		return
	}
	_ = binary.LittleEndian.Uint32(n.buffer[offset : offset+4])
	_ = binary.LittleEndian.Uint32(n.buffer[offset+4 : offset+8])
	_ = binary.LittleEndian.Uint32(n.buffer[offset+8 : offset+12])
	_ = binary.LittleEndian.Uint32(n.buffer[offset+12 : offset+16])
	_ = binary.LittleEndian.Uint16(n.buffer[offset+16 : offset+18])
	_ = binary.LittleEndian.Uint16(n.buffer[offset+18 : offset+20])
	n.cursor = n.cursor + 20
	return
}

func (n *Netlink) DecodeHdr(header *uint32) (err error) {
	offset := n.cursor
	if len(n.buffer[offset:]) < 16 {
		err = ErrTooShort
		return
	}
	*header = binary.LittleEndian.Uint32(n.buffer[offset : offset+4])
	_ = binary.LittleEndian.Uint32(n.buffer[offset+4 : offset+8])
	_ = binary.LittleEndian.Uint32(n.buffer[offset+8 : offset+16])
	n.cursor = n.cursor + 16
	return
}

// linux/cn_proc.h: struct proc_event.fork
func (n *Netlink) DecodeFork(childTgid *uint32, parentTgid *uint32) (err error) {
	offset := n.cursor
	if len(n.buffer[offset:]) < 16 {
		err = ErrTooShort
		return
	}
	_ = binary.LittleEndian.Uint32(n.buffer[offset : offset+4])
	*parentTgid = binary.LittleEndian.Uint32(n.buffer[offset+4 : offset+8])
	_ = binary.LittleEndian.Uint32(n.buffer[offset+8 : offset+12])
	*childTgid = binary.LittleEndian.Uint32(n.buffer[offset+12 : offset+16])
	n.cursor = n.cursor + 16
	return
}

func (n *Netlink) DecodeExec(pid *uint32, tgid *uint32) (err error) {
	offset := n.cursor
	if len(n.buffer[offset:]) < 8 {
		err = ErrTooShort
		return
	}
	*pid = binary.LittleEndian.Uint32(n.buffer[offset : offset+4])
	*tgid = binary.LittleEndian.Uint32(n.buffer[offset+4 : offset+8])
	n.cursor = n.cursor + 8
	return
}

// ptrace
type ProcEventPtrace struct {
	ProcessPid  int32
	ProcessTgid int32
	TracerPid   int32
	TracerTgid  int32
}

func (n *Netlink) Handle(data []byte) (result string, err error) {
	var hdrwhat uint32
	DefaultNetlink.SetBuffer(data)
	if err = DefaultNetlink.DecodeMsg(); err != nil {
		return
	}
	if err = DefaultNetlink.DecodeHdr(&hdrwhat); err != nil {
		return
	}

	switch hdrwhat {
	case PROC_EVENT_NONE:
	// pay attention to tgid & tpid
	case PROC_EVENT_FORK:
		var parentTgid uint32
		var childTgid uint32
		DefaultNetlink.DecodeFork(&childTgid, &parentTgid)
		cache.ProcessCache.Add(childTgid, parentTgid)
	case PROC_EVENT_EXEC:
		var pid uint32
		var tpid uint32
		var process *cache.Process
		DefaultNetlink.DecodeExec(&pid, &tpid)
		// TODO: skip memory here
		process, err = cache.GetProcessInfo(int(pid), true)
		process.Source = "netlink"
		process.TID = int(tpid)
		defer cache.DefaultProcessPool.Put(process)
		if err != nil {
			return
		}
		// whitelist to check
		// filter here
		cache.ProcessCmdlineCache.Add(pid, process.Exe)
		if ppid, ok := cache.ProcessCache.Get(pid); ok {
			process.PPID = int(ppid.(uint32))
		}
		process.PidTree = cache.GetPstree(tpid)
		result, err = share.MarshalString(process)
		return
	// skip exit
	case PROC_EVENT_EXIT:
	case PROC_EVENT_UID:
	case PROC_EVENT_GID:
	case PROC_EVENT_SID:
	// TODO: ptrace
	case PROC_EVENT_PTRACE:
	// TODO: Comm
	case PROC_EVENT_COMM:
	case PROC_EVENT_COREDUMP:
	}
	err = ErrNothing
	return
}

func init() {
	RegistEvent(&Netlink{})
}
