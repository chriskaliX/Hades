package event

import (
	"encoding/binary"
	"errors"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bytedance/sonic"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
)

const (
	CN_IDX_PROC          = 0x1
	CN_VAL_PROC          = 0x1
	PROC_CN_MCAST_LISTEN = 0x1
	PROC_EVENT_FORK      = 0x00000001
	PROC_EVENT_EXEC      = 0x00000002
	PROC_EVENT_EXIT      = 0x80000000
)

const (
	Stop  = 0
	Start = 1
)

type Ncp struct {
	sock   *nl.NetlinkSocket
	buffer []byte
	cursor int
	// internal event
	event *Event
	// status fields
	succCnt uint64
	failCnt uint64
	update  time.Time
	// control fields
	isrunnging bool
	sig        chan struct{}
	close      chan struct{}
}

func New() *Ncp {
	return &Ncp{
		event:  &Event{},
		update: time.Now(),
	}
}

func (n *Ncp) Start(s SDK.ISandbox) (err error) {
	if n.isrunnging {
		return errors.New("ncp is running")
	}
	n.isrunnging = true
	defer func() {
		n.isrunnging = false
	}()
	nlmsg := n.getNetlinkMsg()
	if n.sock, err = nl.SubscribeAt(
		netns.None(),
		netns.None(),
		unix.NETLINK_CONNECTOR,
		CN_IDX_PROC); err != nil {
		return err
	}
	if err = n.sock.Send(&nlmsg); err != nil {
		return err
	}

	// start receiving
	var result string
	var send bool
	rawdata := make(map[string]string, 1)
	for {
		select {
		case <-n.close:
			goto out
		default:
			msgs, from, err := n.sock.Receive()
			if err != nil {
				continue
			}
			// only get from kernel space
			if from.Pid != nl.PidKernel {
				continue
			}
			for _, msg := range msgs {
				if msg.Header.Type != syscall.NLMSG_DONE {
					continue
				}
				n.setBuffer(msg.Data)
				if result, send, err = n.decode(); err != nil {
					atomic.AddUint64(&n.failCnt, 1)
					continue
				}
				// should not send, ignore
				if !send {
					continue
				}
				rawdata["data"] = result
				rec := &protocol.Record{
					DataType: 1000,
					Data: &protocol.Payload{
						Fields: rawdata,
					},
				}
				atomic.AddUint64(&n.succCnt, 1)
				s.SendRecord(rec)
			}
		}
	}
out:
	n.sig <- struct{}{}
	return
}

func (n *Ncp) Stop() (err error) {
	n.close <- struct{}{}
	if n.sock != nil {
		n.sock.Close()
	}
	<-n.sig
	n.isrunnging = false
	return
}

func (n *Ncp) GetState() (succTPS, failTPS float64) {
	now := time.Now()
	instant := now.Sub(n.update).Seconds()
	if instant != 0 {
		succTPS = float64(atomic.SwapUint64(&n.succCnt, 0)) / float64(instant)
		failTPS = float64(atomic.SwapUint64(&n.failCnt, 0)) / float64(instant)
	}
	n.update = now
	return
}

func (n *Ncp) getNetlinkMsg() (nlmsg nl.NetlinkRequest) {
	nlmsg.Pid = uint32(os.Getpid())
	nlmsg.Type = unix.NLMSG_DONE
	nlmsg.Len = uint32(unix.SizeofNlMsghdr)
	nlmsg.AddData(
		nl.NewCnMsg(CN_IDX_PROC, CN_VAL_PROC, PROC_CN_MCAST_LISTEN),
	)
	return
}

func (n *Ncp) setBuffer(buf []byte) {
	n.buffer = n.buffer[:0]
	n.buffer = append(n.buffer, buf...)
	n.cursor = 0
}

func (n *Ncp) decode() (result string, send bool, err error) {
	var header uint32
	if err = n.decodeHdr(&header); err != nil {
		return
	}
	switch header {
	case PROC_EVENT_FORK:
		var tgid, ptgid uint32
		if err = n.decodeFork(&tgid, &ptgid); err != nil {
			return
		}
		pidCache.Add(tgid, ptgid)
		return
	case PROC_EVENT_EXEC:
		send = true
		var pid, tpid uint32
		if err = n.decodeExec(&pid, &tpid); err != nil {
			return
		}
		n.event.Reset()
		n.event.Pid = pid
		n.event.Tid = tpid
		if err = n.event.GetInfo(); err != nil {
			return
		}
		result, err = sonic.MarshalString(n.event)
		return
	default:
		return
	}
}

func (n *Ncp) decodeHdr(header *uint32) (err error) {
	if len(n.buffer) < 20 {
		err = errors.New("hdr buffer length too short")
		return
	}
	n.cursor += 20
	if len(n.buffer[n.cursor:]) < 16 {
		err = errors.New("hdr buffer length too short")
		return
	}
	*header = binary.LittleEndian.Uint32(n.buffer[n.cursor : n.cursor+4])
	n.cursor += 16
	return
}

func (n *Ncp) decodeFork(child, parent *uint32) (err error) {
	if len(n.buffer[n.cursor:]) < 16 {
		err = errors.New("buffer length too short")
		return
	}
	*parent = binary.LittleEndian.Uint32(n.buffer[n.cursor+4 : n.cursor+8])
	*child = binary.LittleEndian.Uint32(n.buffer[n.cursor+12 : n.cursor+16])
	n.cursor = n.cursor + 16
	return
}

func (n *Ncp) decodeExec(pid, tgid *uint32) (err error) {
	if len(n.buffer[n.cursor:]) < 8 {
		err = errors.New("buffer length too short")
		return
	}
	*pid = binary.LittleEndian.Uint32(n.buffer[n.cursor : n.cursor+4])
	*tgid = binary.LittleEndian.Uint32(n.buffer[n.cursor+4 : n.cursor+8])
	n.cursor = n.cursor + 8
	return
}
