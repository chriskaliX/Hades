package main

import (
	"collector/cache"
	"collector/share"
	"collector/socket"
	"context"
	"encoding/json"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/chriskaliX/plugin"
	"go.uber.org/zap"
)

// All like in Elkeid
func SocketJob(ctx context.Context) {
	init := true
	ticker := time.NewTicker(time.Second * time.Duration(rand.Intn(600)+1))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if init {
				ticker.Reset(30 * time.Minute)
				init = false
			}
			var sockets []socket.Socket
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
			if pids, err := GetPids(1000); err == nil {
				for _, pid := range pids {
					if fds, err := cache.GetFds(pid); err == nil {
						for _, fd := range fds {
							if strings.HasPrefix(fd, "socket:[") {
								inode, _ := strconv.ParseUint(strings.TrimRight(fd[8:], "]"), 10, 32)
								index, ok := inodeMap[uint32(inode)]
								if ok {
									sockets[index].PID = pid
									proc := cache.DefaultProcessPool.Get()
									proc.PID = pid
									if err = proc.GetStat(); err == nil {
										sockets[index].Comm = proc.Name
									}
									if err = proc.GetCmdline(); err == nil {
										sockets[index].Cmdline = proc.Cmdline
									}
								}
							}
						}
					}
					time.Sleep(100 * time.Millisecond)
				}
			}

			rec := &plugin.Record{
				DataType:  5001,
				Timestamp: time.Now().Unix(),
			}
			data, _ := json.Marshal(sockets)
			rec.Data = &plugin.Payload{
				Fields: map[string]string{"data": string(data)},
			}
			share.Client.SendRecord(rec)
		case <-ctx.Done():
			return
		}
	}
}
