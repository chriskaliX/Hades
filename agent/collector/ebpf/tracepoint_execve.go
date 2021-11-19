package ebpf

import (
	"agent/global"
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

type enter_execve_t struct {
	Cid      uint64
	Type     uint32
	Pid      uint32
	Tgid     uint32
	Uid      uint32
	Gid      uint32
	Ppid     uint32
	Filename [32]byte
	Comm     [16]byte
	Args     [128]byte
	Argsize  uint32
}

// 今天继续读 perf_events, 发现这么写是有一些问题的, 加到 todo 里后续改进
// TODO:
// 1. 乱序问题, 由于现在开发的机器是腾讯云的单CPU机器, 所以按照这么写永远是有顺序的。周末开一台多核的, 把代码拉上去 run 一下作为验证, 并加上 fork 程序?
// 2. 看 cilium/ebpf/perf/reader.go 实现, 看一下 perCPU ringbuf 大小定义(可能不在这里) 来解决 ring buffer full 导致的 drop 问题
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
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)
	if err != nil {
		zap.S().Error(fmt.Sprintf("opening tracepoint: %s", err))
		return err
	}
	defer tp.Close()

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
		// 这里这么写有问题, 有些特殊情况下, 取回来的数据有问题,本身就是 0
		if pid == 0 {
			pid = event.Pid
		}

		// 涉及到字符串拼接优化
		// https://gosamples.dev/concatenate-strings/
		if pid == event.Pid {
			if event.Argsize > 128 {
				continue
			}
			args = append(args, string(event.Args[:event.Argsize-1]))
			// pid 不同了, 代表一个新的: 这个貌似也会有乱序的问题?
			// TODO: 好好看一下这个问题, 暂时先当没有来写（或者拼接部分我们在 eBPF 中做? 看一下）
		} else {
			fmt.Printf("[INFO] pid: %d, comm: %s, argv: %s\n", event.Pid, string(event.Comm[:]), strings.Join(args, " "))
			pid = event.Pid
			args = args[0:0]
			args = append(args, string(event.Args[:]))
		}
	}
}
