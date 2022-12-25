package event

import (
	"collector/cache/process"
	"collector/eventmanager"
	"collector/socket"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"go.uber.org/zap"
)

// use inode key as primary key
const SOCKET_DATATYPE = 5001

var _ eventmanager.IEvent = (*Socket)(nil)

type Socket struct{}

func (Socket) DataType() int {
	return SOCKET_DATATYPE
}

func (Socket) Name() string {
	return "socket"
}

func (n *Socket) Flag() int { return eventmanager.Periodic }

func (s *Socket) Run(sandbox SDK.ISandbox, sig chan struct{}) error {
	var ok bool
	result := make([]socket.Socket, 0, 128)
	sockets, err := socket.FromNetlink()
	if err != nil {
		zap.S().Warn("get socket from netlink failed:", err)
		zap.S().Info("try getting socket from proc...")
		sockets, _ = socket.FromProc()
	}
	inodeMap := make(map[uint32]int)
	for index, socket := range sockets {
		if socket.Inode != 0 {
			inodeMap[socket.Inode] = index
		}
	}
	// fds & relate here, a thing to be noticed here, should a procCache to speed up this?
	pids, err := process.GetPids(1000)
	if err != nil {
		return err
	}
	for _, pid := range pids {
		var fds []string
		var index int
		// Logical bug here,
		if fds, err = process.GetFds(pid); err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		// get all file description here
		for _, fd := range fds {
			// skip field that is not socket:[
			if !strings.HasPrefix(fd, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimRight(fd[8:], "]"), 10, 32)
			if err != nil {
				continue
			}
			index, ok = inodeMap[uint32(inode)]
			if !ok {
				continue
			}
			sockets[index].PID = pid
			proc := process.Pool.Get()
			proc.PID = pid
			if err = proc.GetStat(false); err == nil {
				sockets[index].Comm = proc.Name
			}
			if err = proc.GetCmdline(); err == nil {
				sockets[index].Cmdline = proc.Argv
			}
			socket := sockets[index]
			result = append(result, socket)
		}
		time.Sleep(100 * time.Millisecond)
	}
	data, err := sonic.MarshalString(result)
	if err != nil {
		return err
	}
	rec := &protocol.Record{
		DataType: 2001,
		Data: &protocol.Payload{
			Fields: map[string]string{
				"data": data,
			},
		},
	}
	sandbox.SendRecord(rec)
	return nil
}
