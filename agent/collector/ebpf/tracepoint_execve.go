package ebpf

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
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

func setlimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
		zap.S().Panic(fmt.Sprintf("failed to set temporary rlimit: %v", err))
	}
}

// 开始看一下 ringbuf 的方案, 要理解原理 和 perf 的区别, example 代码在
// https://github.com/cilium/ebpf/blob/master/examples/ringbuffer/bpf/ringbuffer_example.c
func Tracepoint2() {
	// args := make(map[uint32][]string)
	// errMap := make(map[uint32]uint32)
	setlimit()
	objs := sysExecveObjects{}
	loadSysExecveObjects(&objs, nil)
	link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)

	rd, err := perf.NewReader(objs.PerfEvents, os.Getpagesize())
	if err != nil {
		zap.S().Panic(fmt.Sprintf("read error"))
	}

	// 在运行一段时间后直接卡住了, 目测是卡在 Read 这里, 和我做的小修改有关?
	// 想到了之前 netlink 的问题, 会不会相似?
	// TODO: 需要 debug
	var count int
	for {
		rd.Read()
		fmt.Println(count)
		count++
		// ev, err := rd.Read()
		// if err != nil {
		// 	fmt.Printf("Read fail")
		// }

		// if ev.LostSamples != 0 {
		// 	fmt.Printf("perf event ring buffer full, dropped %d samples\n", ev.LostSamples)
		// 	continue
		// }

		// b_arr := bytes.NewBuffer(ev.RawSample)

		// var data exec_data_t
		// if err := binary.Read(b_arr, binary.LittleEndian, &data); err != nil {
		// 	fmt.Printf("parsing perf event: %s", err)
		// 	continue
		// }

		// if data.Type == 0 {
		// 	// args
		// 	e, ok := args[data.Pid]
		// 	if !ok {
		// 		e = make([]string, 0)
		// 	}
		// 	if data.Arg_size > 127 {
		// 		// abnormal
		// 		errMap[data.Pid] = 1
		// 	} else {
		// 		e = append(e, string(data.Args[:data.Arg_size]))
		// 		args[data.Pid] = e
		// 	}

		// } else {
		// 	argv, ok := args[data.Pid]
		// 	if !ok {
		// 		continue
		// 	}
		// 	if _, ok := errMap[data.Pid]; ok {
		// 		fmt.Printf("[ERROR] bpf_probe_read_str occur error, cmdline: %s\n", strings.TrimSpace(strings.Replace(strings.Join(argv, " "), "\n", "\\n", -1)))
		// 		delete(errMap, data.Pid)
		// 	}

		// 	fmt.Printf("[INFO] Pid: %d %s\n", data.Pid, strings.TrimSpace(strings.Replace(strings.Join(argv, " "), "\n", "\\n", -1)))
		// 	delete(args, data.Pid)
		// }
	}
}
