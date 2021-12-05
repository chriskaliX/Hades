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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

type Objs struct {
	TracerPrograms
	Readers
}

type TracerPrograms struct {
	TpExecve   *ebpf.Program `ebpf:"enter_execve"`
	TpExecveat *ebpf.Program `ebpf:"enter_execveat"`
	TpFork     *ebpf.Program `ebpf:"process_fork"`
}

type Readers struct {
	PerfEvents *ebpf.Map `ebpf:"perf_events"`
}

func Tracer() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		zap.S().Error(err)
		return err
	}
	// 测试, 先写死
	sepc, err := ebpf.LoadCollectionSpec("/root/projects/Hades/agent/collector/ebpf/tracer/tracer.o")
	if err != nil {
		zap.S().Error(err)
		return err
	}

	object := Objs{}

	err = sepc.LoadAndAssign(&object, nil)
	if err != nil {
		zap.S().Error(err)
		return err
	}

	sched_process_fork, err := link.Tracepoint("sched", "sched_process_fork", object.TpFork)
	if err != nil {
		zap.S().Error(err)
		return err
	}
	defer sched_process_fork.Close()

	execve, err := link.Tracepoint("syscalls", "sys_enter_execve", object.TpExecve)
	if err != nil {
		zap.S().Error(err)
		return err
	}
	defer execve.Close()

	rd, err := perf.NewReader(object.PerfEvents, 4*os.Getpagesize())
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
	var pcomm string
	var lastpid int
	var lastppid int
	var lastcid int
	var lasttid int
	var lastnodename string
	var lastpns int

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
			comm = formatByte(event.Comm[:])
			pcomm = formatByte(event.PComm[:])
			lastpid = int(event.Pid)
			lastppid = int(event.Ppid)
			lastcid = int(event.Cid)
			lasttid = int(event.Tid)
			lastpns = int(event.Pns)
			lastnodename = string(bytes.Trim(event.Nodename[:], "\x00"))
			// TODO: 好好看一下这个问题, 暂时先当没有来写（或者拼接部分我们在 eBPF 中做? 看一下）
		} else {
			// TODO: 字段不全的, 需要补
			// syscall, fd, source(cnproc or ebpf), timestamp
			// TODO: 偶尔有进程树不全的问题, 看一下 pid , tid

			// 临时的 patch, 先 run 起来, 后面会优雅一点解决
			if len(args) == 1 {
				filename = string(bytes.Trim(event.Filename[:], "\x00"))
				comm = formatByte(event.Comm[:])
				pcomm = formatByte(event.PComm[:])
				lastpid = int(event.Pid)
				lastppid = int(event.Ppid)
				lastcid = int(event.Cid)
				lasttid = int(event.Tid)
				lastpns = int(event.Pns)
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
			process.Source = "ebpf"
			process.PName = pcomm
			process.Pns = lastpns

			// TODO: 这个 LRU 其实可以合并的
			global.ProcessCmdlineCache.Add(uint32(process.PID), process.Exe)
			global.ProcessCache.Add(uint32(process.PID), uint32(process.PPID))

			process.PidTree = global.GetPstree(uint32(process.PID))
			process.Sha256, _ = common.GetFileHash(process.Exe)
			process.UID = strconv.Itoa(int(event.Uid))
			process.Username = global.GetUsername(process.UID)
			process.StartTime = uint64(global.Time)
			data, err := utils.Marshal(process)
			if err == nil {
				rawdata["data"] = string(data)
				global.UploadChannel <- rawdata
			}
			process.Reset()
			structs.ProcessPool.Put(process)
			pid = event.Pid
			args = args[0:0]
			args = append(args, formatByte(event.Args[:]))
		}
	}
}
