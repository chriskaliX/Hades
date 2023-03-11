package networks

import (
	"collector/cache/process"
	scache "collector/cache/socket"
	"collector/eventmanager"
	"collector/socket"
	"collector/utils"
	"strconv"
	"strings"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
)

var _ eventmanager.IEvent = (*Socket)(nil)

type Socket struct{}

func (Socket) DataType() int { return 5001 }

func (Socket) Name() string { return "socket" }

func (n *Socket) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (Socket) Immediately() bool { return true }

func (s *Socket) Run(sandbox SDK.ISandbox, sig chan struct{}) error {
	var ok bool
	hash := utils.Hash()
	sockets, err := socket.FromNetlink()
	if err != nil {
		zap.S().Warn("get socket from netlink failed:", err)
		zap.S().Info("try getting socket from proc...")
		sockets, _ = socket.FromProc()
	}
	inodeMap := make(map[string]int)
	for index, socket := range sockets {
		if socket.Inode != "0" {
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
			index, ok = inodeMap[strconv.FormatUint(uint64(inode), 10)]
			if !ok {
				continue
			}
			sockets[index].PID = strconv.Itoa(pid)
			proc := &process.Process{
				PID: pid,
			}
			if err = proc.GetStat(false); err == nil {
				sockets[index].Comm = proc.Name
			}
			if err = proc.GetCmdline(); err == nil {
				sockets[index].Cmdline = proc.Argv
			}
			socket := sockets[index]
			scache.Put(uint32(inode), socket)
			rec := &protocol.Record{
				DataType: int32(s.DataType()),
				Data: &protocol.Payload{
					Fields: make(map[string]string, 15),
				},
			}
			mapstructure.Decode(&socket, &rec.Data.Fields)
			rec.Data.Fields["package_seq"] = hash
			sandbox.SendRecord(rec)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func init() { addEvent(&Socket{}, 15*time.Minute) }
