package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
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
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}
}

func Tracepoint2() {
	args := make(map[uint32][]string)
	errMap := make(map[uint32]uint32)
	setlimit()

	objs := sysExecveObjects{}

	loadSysExecveObjects(&objs, nil)
	link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)

	rd, err := perf.NewReader(objs.ExecvePerfMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("reader err")
	}

	for {
		ev, err := rd.Read()
		if err != nil {
			log.Fatalf("Read fail")
		}

		if ev.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", ev.LostSamples)
			continue
		}

		b_arr := bytes.NewBuffer(ev.RawSample)

		var data exec_data_t
		if err := binary.Read(b_arr, binary.LittleEndian, &data); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		if data.Type == 0 {
			// args
			e, ok := args[data.Pid]
			if !ok {
				e = make([]string, 0)
			}
			if data.Arg_size > 127 {
				// abnormal
				errMap[data.Pid] = 1
			} else {
				e = append(e, string(data.Args[:data.Arg_size]))
				args[data.Pid] = e
			}

		} else {
			argv, ok := args[data.Pid]
			if !ok {
				continue
			}
			if _, ok := errMap[data.Pid]; ok {
				fmt.Printf("[ERROR] bpf_probe_read_str occur error, cmdline: %s\n", strings.TrimSpace(strings.Replace(strings.Join(argv, " "), "\n", "\\n", -1)))
				delete(errMap, data.Pid)
			}

			fmt.Printf("[INFO] Pid: %d <Cmdline> %s\n", data.Pid, strings.TrimSpace(strings.Replace(strings.Join(argv, " "), "\n", "\\n", -1)))
			delete(args, data.Pid)
		}
	}
}
