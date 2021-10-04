package collector

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-12 KProbeExample ./ebpf/ebpf.c -- -nostdinc -I/root/projects/Hades/agent/collector/ebpf/headers/ -g -O2 -target bpf -D__TARGET_ARCH_x86

// ebpf 的采集 - test1
// osquery 的 ebpf 相关地址 https://github.com/osquery/osquery/tree/d2be385d71f401c85872f00d479df8f499164c5a/osquery/events/linux/bpf

const mapKey uint32 = 0

func EbpfGather() {
	// Name of the kernel function to trace
	fn := "sys_execve"

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	rrl, err := ebpf.RemoveMemlockRlimit()
	if err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := KProbeExampleObjects{}
	if err := LoadKProbeExampleObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Revert the process' rlimit after eBPF resources have been loaded.
	if err := rrl(); err != nil {
		log.Fatal(err)
	}

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.BpfSysExecve)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Millisecond)

	// 一个reader
	rd, err := perf.NewReader(objs.ExecveEvents, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	log.Println("Waiting for events..")

	var event Event

	for {
		select {
		case <-ticker.C:
			// var value uint64
			// if err := objs.ExecveEvents.Lookup(mapKey, &value); err != nil {
			// 	log.Fatalf("reading map: %v", err)
			// }

			// log.Printf("%s called %d times\n", fn, value)
			record, err := rd.Read()
			if err != nil {
				if perf.IsClosed(err) {
					return
				}
				log.Printf("reading from perf event reader: %s", err)
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

			// log.Printf("pid: %d, uid: %d, return value: %s, arg: %s", event.PID, event.UID, unix.ByteSliceToString(event.Comm[:]), unix.ByteSliceToString(event.Argv[:]))
			if unix.ByteSliceToString(event.Comm[:]) == "cpuUsage.sh" {
				continue
			} else if unix.ByteSliceToString(event.Comm[:]) == "node" {
				continue
			} else if unix.ByteSliceToString(event.Comm[:]) == "watchdog.sh" {
				continue
			} else if unix.ByteSliceToString(event.Comm[:]) != "bash" {
				continue
			}
			log.Printf("ppid: %d, pid: %d, uid: %d, return value: %s, arg: %s", event.PPID, event.PID, event.UID, unix.ByteSliceToString(event.Comm[:]), unix.ByteSliceToString(event.Argv[:]))
			log.Println(unix.ByteSliceToString(event.Argv[:]), event.Argv[:])

		case <-stopper:
			log.Fatal("goodbye")
			return
		}
	}
}

type Event struct {
	PID  uint32
	UID  uint32
	GID  uint32
	PPID uint32
	Comm [16]byte
	Argv [256]byte
}
