package main

import (
	"context"
	"encoding/json"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"collector/network"
	"collector/share"

	"github.com/chriskaliX/plugin"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

var (
	nlSocketContext     *network.Context
	nlSocketSingleton   *network.VNetlink
	nlSocketContextOnce sync.Once
	nlSocketOnce        sync.Once
)

func GetNlSocketContext() *network.Context {
	nlSocketContextOnce.Do(func() {
		nlSocketContext = &network.Context{}
	})
	return nlSocketContext
}

func GetNlSocketSingleton() *network.VNetlink {
	nlSocketOnce.Do(func() {
		nlSocketSingleton = &network.VNetlink{}
	})
	return nlSocketSingleton
}

// netlink 方式获取
func GetSockets(disableProc bool, status uint8) (sockets []network.Socket, err error) {
	var udpSockets, udp6Sockets, tcpSockets, tcp6Sockets []network.Socket
	ctx := GetNlSocketContext()
	nlsocket := GetNlSocketSingleton()
	// 先初始化协议
	nlsocket.Protocal = unix.NETLINK_INET_DIAG
	if err = ctx.IRetry(nlsocket); err != nil {
		return
	}

	if status != network.TCP_ESTABLISHED {
		if udpSockets, err = nlsocket.GetSockets(unix.AF_INET, unix.IPPROTO_UDP, status); err != nil {
			return
		}
		sockets = append(sockets, udpSockets...)
		udp6Sockets, err = nlsocket.GetSockets(unix.AF_INET6, unix.IPPROTO_UDP, status)
		if err == nil {
			sockets = append(sockets, udp6Sockets...)
		}
	}

	tcpSockets, err = nlsocket.GetSockets(unix.AF_INET, unix.IPPROTO_TCP, status)
	if err == nil {
		sockets = append(sockets, tcpSockets...)
	}
	tcp6Sockets, err = nlsocket.GetSockets(unix.AF_INET6, unix.IPPROTO_TCP, status)
	if err == nil {
		sockets = append(sockets, tcp6Sockets...)
	}

	inodeMap := make(map[uint32]int)
	for index, socket := range sockets {
		if socket.Inode != 0 {
			inodeMap[socket.Inode] = index
		}
	}
	if !disableProc {
		procs, err := procfs.AllProcs()
		if err == nil {
			for _, p := range procs {
				fds, _ := p.FileDescriptorTargets()
				for _, fd := range fds {
					if strings.HasPrefix(fd, "socket:[") {
						inode, _ := strconv.ParseUint(strings.TrimRight(fd[8:], "]"), 10, 32)
						index, ok := inodeMap[uint32(inode)]
						if ok {
							sockets[index].PID = int32(p.PID)
							sockets[index].Comm, _ = p.Comm()
							argv, err := p.CmdLine()
							if err == nil {
								if len(argv) > 16 {
									argv = argv[:16]
								}
								sockets[index].Argv = strings.Join(argv, " ")
								if len(sockets[index].Argv) > 32 {
									sockets[index].Argv = sockets[index].Argv[:32]
								}
							}
						}
					}
				}
			}
		}
	}
	return
}

// 在同一时间突然流量激增导致丢弃，给一个初始随机值，再reset掉
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
			// 是否开启proc，统一关闭先
			if socks, err := GetSockets(false, network.TCP_ESTABLISHED); err == nil {
				if data, err := json.Marshal(socks); err == nil {
					rawdata := make(map[string]string)
					rawdata["data"] = string(data)
					rec := &plugin.Record{
						DataType:  1001,
						Timestamp: time.Now().Unix(),
						Data: &plugin.Payload{
							Fields: rawdata,
						},
					}
					share.Client.SendRecord(rec)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
