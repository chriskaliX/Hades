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

type exec_data_t struct {
	Type     uint32
	Pid      uint32
	Tgid     uint32
	Uid      uint32
	Gid      uint32
	Ppid     uint32
	F_name   [32]byte
	Comm     [16]byte
	Args     [128]byte
	Arg_size uint32
}

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
	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	rd, err := perf.NewReader(objs.PerfEvents, os.Getpagesize())
	if err != nil {
		fmt.Println(err)
	}
	defer rd.Close()
	var event exec_data_t
	log.Println("Waiting for events..")
	var args string
	var pid uint32
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
			args = args + string(event.Args[:event.Arg_size]) + " "

		} else {
			fmt.Printf("[INFO] pid: %d, comm: %s, argv: %s\n", event.Pid, string(event.Comm[:]), strings.Trim(args, " "))
			pid = event.Pid
			args = string(event.Args[:]) + " "
		}

		// fmt.Println(event.Args)
	}
}
