package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-12 sysExecve ./src/tracepoint_execve.c -- -nostdinc -I headers/

type enter_execve_t struct {
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

func Tracepoint3() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := sysExecveObjects{}
	if err := loadSysExecveObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	// 第二个参数为每一个 CPU 对应的 buffer 大小
	rd, err := perf.NewReader(objs.PerfEvents, 2*os.Getpagesize())
	if err != nil {
		fmt.Println(err)
	}
	defer rd.Close()

	var event enter_execve_t

	log.Println("Waiting for events..")
	var args string
	var pid uint32
	var count int
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into an Event structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		// 如果 pid 为 0, 赋值
		if pid == 0 {
			pid = event.Pid
		}

		// 相等则拼接
		if pid == event.Pid {
			args = args + string(event.Args[:event.Argsize]) + " "
		} else {
			fmt.Printf("[INFO] pid: %d, comm: %s, argv: %s\n", event.Pid, string(event.Comm[:]), strings.Trim(args, " "))

			count = count + 1
			pid = event.Pid
			args = string(event.Args[:]) + " "
		}
	}
}
