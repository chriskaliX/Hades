package event

import (
	"collector/cache"
	"collector/socket"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// use inode key as primary key
const SOCKET_DATATYPE = 5001

var _ Event = (*Socket)(nil)

type Socket struct {
	BasicEvent
}

func (Socket) DataType() int {
	return SOCKET_DATATYPE
}

func (Socket) String() string {
	return "socket"
}

func (s Socket) Run() (result map[string]interface{}, err error) {
	result = make(map[string]interface{})
	var (
		sockets []socket.Socket
		pids    []int
		inode   uint64
		index   int
		ok      bool
	)

	sockets, err = socket.FromNetlink()
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
	if pids, err = cache.GetPids(1000); err != nil {
		return
	}
	for _, pid := range pids {
		var fds []string
		if fds, err = cache.GetFds(pid); err != nil {
			goto Next
		}
		// get all file description here
		for _, fd := range fds {
			// skip field that is not socket:[
			if !strings.HasPrefix(fd, "socket:[") {
				continue
			}
			inode, err = strconv.ParseUint(strings.TrimRight(fd[8:], "]"), 10, 32)
			if err != nil {
				continue
			}
			index, ok = inodeMap[uint32(inode)]
			if !ok {
				continue
			}
			sockets[index].PID = pid
			proc := cache.DefaultProcessPool.Get()
			proc.PID = pid
			if err = proc.GetStat(false); err == nil {
				sockets[index].Comm = proc.Name
			}
			if err = proc.GetCmdline(); err == nil {
				sockets[index].Cmdline = proc.Cmdline
			}
		}
	Next:
		socket := sockets[index]
		result[strconv.Itoa(int(socket.Inode))] = socket
		time.Sleep(100 * time.Millisecond)
	}
	return
}

func init() {
	RegistEvent(&Socket{})
}
