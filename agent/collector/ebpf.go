package collector

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-12 KProbeExample ./ebpf/ebpf.c -- -nostdinc -I/root/projects/Hades/agent/collector/ebpf/headers/

// ebpf 的采集 - test
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
	ticker := time.NewTicker(1 * time.Second)

	log.Println("Waiting for events..")

	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := objs.ExecveEvents.Lookup(mapKey, &value); err != nil {
				log.Fatalf("reading map: %v", err)
			}
			log.Printf("%s called %d times\n", fn, value)
		case <-stopper:
			return
		}
	}
}
