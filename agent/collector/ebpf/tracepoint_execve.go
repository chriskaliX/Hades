package ebpf

import (
	"agent/collector/common"
	"agent/global"
	"agent/global/structs"
	"agent/utils"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-12 sysExecve ./src/tracepoint_execve.c -- -nostdinc -I headers/

// syncpool
type enter_execve_t struct {
	Ts       uint64
	Cid      uint64
	Type     uint32
	Pid      uint32
	Tid      uint32
	Uid      uint32
	Gid      uint32
	Ppid     uint32
	Argsize  uint32
	Filename [32]byte
	Comm     [16]byte
	Args     [128]byte
	Nodename [65]byte
}

func Tracepoint_execve() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		zap.S().Error(err)
		return err
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := sysExecveObjects{}
	if err := loadSysExecveObjects(&objs, nil); err != nil {
		zap.S().Error(err)
		return err
	}
	defer objs.Close()

	sched_process_fork, err := link.Tracepoint("sched", "sched_process_fork", objs.ProcessFork)
	if err != nil {
		zap.S().Error(fmt.Sprintf("opening tracepoint: %s", err))
		return err
	}
	defer sched_process_fork.Close()

	sys_enter_execve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)
	if err != nil {
		zap.S().Error(fmt.Sprintf("opening tracepoint: %s", err))
		return err
	}
	defer sys_enter_execve.Close()

	// TODO: under test
	sys_enter_execveat, err := link.Tracepoint("syscalls", "sys_enter_execveat", objs.EnterExecveat)
	if err != nil {
		zap.S().Error(fmt.Sprintf("opening tracepoint: %s", err))
		return err
	}
	defer sys_enter_execveat.Close()

	// 第二个参数为每一个 CPU 对应的 buffer 大小, 搜索了一下, 最大貌似只能是 64KB, 我们先定在 16
	rd, err := perf.NewReader(objs.PerfEvents, 4*os.Getpagesize())
	if err != nil {
		zap.S().Error(err)
		return err
	}
	defer rd.Close()

	var event enter_execve_t

	args := make([]string, 0)

	var pid uint32
	var filename string
	var comm string
	var lastpid int
	var lastppid int
	var lastcid int
	var lasttid int
	var lastnodename string

	// 用户态 reordering 问题, 如果不 reorder,  pstree 有问题
	// 感觉实现类似于 Flink WaterMark order 问题, 目前考虑是: 优先队列缓冲 + 根据 ts 排序
	// https://github.com/iovisor/bcc/issues/2299
	// https://kinvolk.io/blog/2018/02/timing-issues-when-using-bpf-with-virtual-cpus/
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return err
			}
			zap.S().Info(fmt.Sprintf("reading from perf event reader: %s", err))
			continue
		}

		// drop 信息很重要, 上传
		if record.LostSamples != 0 {
			rawdata := make(map[string]string)
			rawdata["data"] = fmt.Sprintf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			rawdata["time"] = strconv.Itoa(int(global.Time))
			rawdata["data_type"] = "999"
			global.UploadChannel <- rawdata
			zap.S().Info(fmt.Sprintf("perf event ring buffer full, dropped %d samples", record.LostSamples))
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			zap.S().Error(err)
			continue
		}

		// 如果 pid 为 0, 赋值
		// TODO: 兼容性, 这里这么写有问题, 有些特殊情况下, 取回来的数据有问题,本身就是 0
		if pid == 0 {
			pid = event.Pid
		}

		// TODO: bugs - 这里有一个问题, 有些时候会出现 repeat 的情况
		// Patch the reordering stuff
		if pid == event.Pid {
			if event.Argsize > 128 {
				continue
			}
			args = append(args, string(bytes.Trim(event.Args[:event.Argsize-1], "\x00")))
			filename = string(bytes.Trim(event.Filename[:], "\x00"))
			comm = string(bytes.Trim(event.Comm[:], "\x00"))
			lastpid = int(event.Pid)
			lastppid = int(event.Ppid)
			lastcid = int(event.Cid)
			lasttid = int(event.Tid)
			lastnodename = string(bytes.Trim(event.Nodename[:], "\x00"))
			// TODO: 好好看一下这个问题, 暂时先当没有来写（或者拼接部分我们在 eBPF 中做? 看一下）
		} else {
			// TODO: 字段不全的, 需要补
			// syscall, fd, source(cnproc or ebpf), timestamp
			// TODO: 偶尔有进程树不全的问题, 看一下 pid , tid

			// 临时的 patch, 先 run 起来, 后面会优雅一点解决
			if len(args) == 1 {
				filename = string(bytes.Trim(event.Filename[:], "\x00"))
				comm = string(bytes.Trim(event.Comm[:], "\x00"))
				lastpid = int(event.Pid)
				lastppid = int(event.Ppid)
				lastcid = int(event.Cid)
				lasttid = int(event.Tid)
				lastnodename = string(string(bytes.Trim(event.Nodename[:], "\x00")))
			}

			rawdata := make(map[string]string)
			rawdata["data_type"] = "1000"
			rawdata["time"] = strconv.Itoa(int(global.Time))
			process := structs.ProcessPool.Get().(structs.Process)
			process.Cmdline = strings.Join(args, " ")
			process.Exe = filename
			process.Name = comm
			process.PID = lastpid
			process.CID = lastcid
			process.TID = lasttid
			process.PPID = lastppid
			process.NodeName = lastnodename

			// TODO: 这个 LRU 其实可以合并的
			global.ProcessCmdlineCache.Add(uint32(process.PID), process.Exe)
			global.ProcessCache.Add(uint32(process.PID), uint32(process.PPID))

			process.PidTree = global.GetPstree(uint32(process.PID))
			process.Sha256, _ = common.GetFileHash(process.Exe)
			process.UID = strconv.Itoa(int(event.Uid))
			process.Username = global.GetUsername(process.UID)
			process.StartTime = uint64(event.Ts) // TODO: 时间范围格式
			data, err := utils.Marshal(process)
			if err == nil {
				rawdata["data"] = string(data)
				global.UploadChannel <- rawdata
			}
			process.Reset()
			structs.ProcessPool.Put(process)
			pid = event.Pid
			args = args[0:0]
			args = append(args, string(bytes.Trim(event.Args[:event.Argsize-1], "\x00")))
		}
	}
}
