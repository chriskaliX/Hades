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

// @TODO: /proc/net/packet
// https://github.com/osquery/osquery/blob/f9282c0f03d049e0f13670afa2cf8a87f8ddf0cc/osquery/filesystem/linux/proc.cpp
// osquery中用户态获取socket方式 https://github.com/osquery/osquery/blob/f9282c0f03d049e0f13670afa2cf8a87f8ddf0cc/osquery/tables/networking/linux/process_open_sockets.cpp
// 在 osquery issue 1094 中(https://github.com/osquery/osquery/issues/1094) 解释了为什么剔除了用 netlink 获取的方式
// 大致为 netlink 的方式在 CentOS/RHEL6 不稳定, 经常会 fallback
// 可以看到之前 readnetlink 他们也有出现 timeout 的情况 https://github.com/osquery/osquery/pull/543
// 其他相关 issue: https://github.com/osquery/osquery/issues/671
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
