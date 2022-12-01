package event

import (
	"collector/cache/process"
	"collector/share"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"time"

	"github.com/bytedance/sonic"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

var (
	errTooShort = errors.New("buffer too short")
	errIngore   = errors.New("ingore")
)

const (
	CN_IDX_PROC          = 0x1
	CN_VAL_PROC          = 0x1
	PROC_CN_MCAST_LISTEN = 0x1
	PROC_EVENT_FORK      = 0x00000001
	PROC_EVENT_EXEC      = 0x00000002
	PROC_EVENT_EXIT      = 0x80000000
	Netlink_DATATYPE     = 1000
)

var _ Event = (*Netlink)(nil)

type Netlink struct {
	buffer   []byte
	cursor   int
	sock     *nl.NetlinkSocket
	rlimiter *rate.Limiter

	BasicEvent
}

func (n *Netlink) DataType() int {
	return Netlink_DATATYPE
}

func (n *Netlink) String() string {
	return "ncp"
}

func (n *Netlink) Init(name string) (err error) {
	n.BasicEvent.Init(name)
	// ratelimiter not that accurate in Millisecond way
	n.rlimiter = rate.NewLimiter(rate.Every(2*time.Millisecond), 200)
	var nlmsg nl.NetlinkRequest
	nlmsg.Pid = uint32(os.Getpid())
	nlmsg.Type = unix.NLMSG_DONE
	nlmsg.Len = uint32(unix.SizeofNlMsghdr)
	// PROC_CN_MCAST_LISTEN be careful
	nlmsg.AddData(
		nl.NewCnMsg(CN_IDX_PROC, CN_VAL_PROC, PROC_CN_MCAST_LISTEN),
	)
	if n.sock, err = nl.SubscribeAt(
		netns.None(),
		netns.None(),
		unix.NETLINK_CONNECTOR,
		CN_IDX_PROC); err != nil {
		return err
	}
	n.sock.Send(&nlmsg)
	return nil
}

func (n *Netlink) RunSync(ctx context.Context) (err error) {
	var result string
	rawdata := make(map[string]string)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// always receive
			msgs, from, err := n.sock.Receive()
			if err != nil {
				continue
			}
			if from.Pid != nl.PidKernel {
				continue
			}
			for _, msg := range msgs {
				if msg.Header.Type != syscall.NLMSG_DONE {
					continue
				}
				n.SetBuffer(msg.Data)
				if result, err = n.Handle(); err != nil {
					continue
				}
				rawdata["data"] = result
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

func (n *Netlink) SetBuffer(buf []byte) {
	n.buffer = n.buffer[:0]
	n.buffer = append(n.buffer, buf...)
	n.cursor = 0
}

func (n *Netlink) DecodeMsg() (err error) {
	if len(n.buffer[n.cursor:]) < 20 {
		err = errTooShort
		return
	}
	n.cursor = n.cursor + 20
	return
}

func (n *Netlink) DecodeHdr(header *uint32) (err error) {
	if len(n.buffer[n.cursor:]) < 16 {
		err = errTooShort
		return
	}
	*header = binary.LittleEndian.Uint32(n.buffer[n.cursor : n.cursor+4])
	n.cursor = n.cursor + 16
	return
}

func (n *Netlink) DecodeFork(child *uint32, parent *uint32) (err error) {
	if len(n.buffer[n.cursor:]) < 16 {
		err = errTooShort
		return
	}
	// only tgid is used
	*parent = binary.LittleEndian.Uint32(n.buffer[n.cursor+4 : n.cursor+8])
	*child = binary.LittleEndian.Uint32(n.buffer[n.cursor+12 : n.cursor+16])
	n.cursor = n.cursor + 16
	return
}

func (n *Netlink) DecodeExec(pid *uint32, tgid *uint32) (err error) {
	if len(n.buffer[n.cursor:]) < 8 {
		err = errTooShort
		return
	}
	*pid = binary.LittleEndian.Uint32(n.buffer[n.cursor : n.cursor+4])
	*tgid = binary.LittleEndian.Uint32(n.buffer[n.cursor+4 : n.cursor+8])
	n.cursor = n.cursor + 8
	return
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
	case PROC_EVENT_FORK:
		var parentTgid, childTgid uint32
		if err = n.DecodeFork(&childTgid, &parentTgid); err != nil {
			return
		}
		process.PidCache.Add(int(childTgid), int(parentTgid))
		// Only add in cache, not event report needed
		err = errIngore
		return
	case PROC_EVENT_EXEC:
		if !n.rlimiter.Allow() {
			err = errIngore
			return
		}
		var pid, tpid uint32
		var p *process.Process
		if err = n.DecodeExec(&pid, &tpid); err != nil {
			return
		}
		p, err = process.GetProcessInfo(int(pid), true)
		p.Source = "netlink"
		defer process.Pool.Put(p)
		if err != nil {
			return
		}
		// TODO: filter here
		p.TID = int(tpid)
		p.PidTree = process.GetPidTree(int(tpid))
		if argv, ok := process.ArgvCache.Get(p.PGID); ok {
			p.PgidArgv = argv.(string)
		}
		result, err = sonic.MarshalString(p)
		return
	default:
		// PROC_EVENT_EXIT not record for now
		err = errIngore
		return
	}
}

func init() {
	RegistEvent(&Netlink{})
}
