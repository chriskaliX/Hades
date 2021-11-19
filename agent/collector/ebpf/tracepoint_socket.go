package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-12 sockets ./src/tracepoint_socket.c -- -nostdinc -I headers/

type netevent_t struct {
	Cid           uint64
	Type          uint32
	Tid           uint32
	Pid           uint32
	PPid          uint32
	Uid           uint32
	Gid           uint32
	RemoteAddress uint32
	RemotePort    uint16
	Family        uint16
	Comm          [16]byte
}

func Tracepoint_sockets() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := socketsObjects{}
	if err := loadSocketsObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	defer objs.Close()
	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.EnterConnect)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()
	rd, err := perf.NewReader(objs.PerfEvents, 2*os.Getpagesize())
	if err != nil {
		fmt.Println(err)
	}
	defer rd.Close()

	var event netevent_t
	log.Println("Waiting for events..")
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
		fmt.Printf("[INFO] pid: %d, family: %d, addr: %s, comm: %s\n", event.Pid, event.Family, InetNtoA_test(event.RemoteAddress)+":"+InetNtoA_test16(event.RemotePort), string(event.Comm[:]))
	}
}

func InetNtoA_test(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// 理解的不够深刻, 抽空看一下
func InetNtoA_test16(ip uint16) string {
	return fmt.Sprintf("%d", int(byte(ip))*256+int(byte(ip>>8)))
}

func htons(val uint16) []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, val)
	return bytes
}
