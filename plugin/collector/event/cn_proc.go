package event

import (
	"collector/cache"
	"collector/share"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"syscall"

	"github.com/bytedance/sonic"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

var (
	ErrTooShort = errors.New("buffer too short")
	errIngore   = errors.New("ingore")
)

const (
	CN_IDX_PROC          = 0x1
	CN_VAL_PROC          = 0x1
	PROC_CN_MCAST_LISTEN = 0x1
	PROC_EVENT_NONE      = 0x00000000
	PROC_EVENT_FORK      = 0x00000001
	PROC_EVENT_EXEC      = 0x00000002
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

func (n *Netlink) DataType() int {
	return Netlink_DATATYPE
}

func (n *Netlink) String() string {
	return "ncp"
}

func (n *Netlink) Init(name string) (err error) {
	var nlmsg nl.NetlinkRequest
	n.BasicEvent.Init(name)
	if n.sock, err = nl.SubscribeAt(
		netns.None(),
		netns.None(),
		unix.NETLINK_CONNECTOR,
		CN_IDX_PROC); err != nil {
		return err
	}
	nlmsg.Pid = uint32(os.Getpid())
	nlmsg.Type = unix.NLMSG_DONE
	nlmsg.Len = uint32(unix.SizeofNlMsghdr)
	// PROC_CN_MCAST_LISTEN be careful
	cm := nl.NewCnMsg(CN_IDX_PROC, CN_VAL_PROC, PROC_CN_MCAST_LISTEN)
	nlmsg.AddData(cm)
	n.sock.Send(&nlmsg)
	return nil
}

// TODO: The speed control things in here
func (n *Netlink) RunSync(ctx context.Context) (err error) {
	var result string
	rawdata := make(map[string]string)
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
					n.SetBuffer(msg.Data)
					if result, err = n.Handle(); err != nil {
						continue
					}
					rawdata["data"] = string(result)
					rec := &protocol.Record{
						DataType: Netlink_DATATYPE,
						Data: &protocol.Payload{
							Fields: rawdata,
						},
					}
					share.Sandbox.SendRecord(rec)
				}
			}
		}
	}
}

func (n *Netlink) SetBuffer(_byte []byte) {
	n.buffer = n.buffer[:0]
	n.buffer = append(n.buffer, _byte...)
	n.cursor = 0
}

func (n *Netlink) DecodeMsg() (err error) {
	offset := n.cursor
	if len(n.buffer[offset:]) < 20 {
		err = ErrTooShort
		return
	}
	// _ = binary.LittleEndian.Uint32(n.buffer[offset : offset+4])
	// _ = binary.LittleEndian.Uint32(n.buffer[offset+4 : offset+8])
	// _ = binary.LittleEndian.Uint32(n.buffer[offset+8 : offset+12])
	// _ = binary.LittleEndian.Uint32(n.buffer[offset+12 : offset+16])
	// _ = binary.LittleEndian.Uint16(n.buffer[offset+16 : offset+18])
	// _ = binary.LittleEndian.Uint16(n.buffer[offset+18 : offset+20])
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
	// _ = binary.LittleEndian.Uint32(n.buffer[offset+4 : offset+8])
	// _ = binary.LittleEndian.Uint32(n.buffer[offset+8 : offset+16])
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

// Real handle function callback
func (n *Netlink) Handle() (result string, err error) {
	var hdrwhat uint32
	if err = n.DecodeMsg(); err != nil {
		return
	}
	if err = n.DecodeHdr(&hdrwhat); err != nil {
		return
	}
	switch hdrwhat {
	// pay attention to tgid & tpid
	case PROC_EVENT_FORK:
		var parentTgid uint32
		var childTgid uint32
		n.DecodeFork(&childTgid, &parentTgid)
		cache.PidCache.Add(int(childTgid), int(parentTgid))
		// Only add in cache, not event report needed
		err = errIngore
		return
	case PROC_EVENT_EXEC:
		var pid uint32
		var tpid uint32
		var process *cache.Process
		if err = n.DecodeExec(&pid, &tpid); err != nil {
			return
		}
		process, err = cache.GetProcessInfo(int(pid), true)
		process.Source = "netlink"
		defer cache.DProcessPool.Put(process)
		if err != nil {
			return
		}
		// whitelist to check
		// filter here
		process.TID = int(tpid)
		process.PidTree = cache.GetPidTree(int(tpid))
		result, err = sonic.MarshalString(process)
		return
	// skip exit
	case PROC_EVENT_EXIT:
		err = errIngore
		return
	default:
		err = errIngore
		return
	}
	return
}

func init() {
	RegistEvent(&Netlink{})
}
