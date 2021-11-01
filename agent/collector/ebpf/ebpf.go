package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-12 bpf ./src/kprobe_example.c -- -nostdinc -g -O2 -target bpf -D__x86_64__ -Wno-address-of-packed-member -I headers/ -I /usr/include/ -I /usr/include/x86_64-linux-gnu/

// ebpf 的采集 - test1
// osquery 的 ebpf 相关地址 https://github.com/osquery/osquery/tree/d2be385d71f401c85872f00d479df8f499164c5a/osquery/events/linux/bpf

const mapKey uint32 = 0

type Event struct {
	PID      uint32
	UID      uint32
	GID      uint32
	PPID     uint32
	Filename [128]byte
	Comm     [16]byte
	Argv     [128]byte
}

func Test() {
	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.ProbeSysExecve)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Millisecond)

	log.Println("Waiting for events..")

	for {
		select {
		case <-ticker.C:
			// var value uint64
			// if err := objs.ExeEvents.Lookup(mapKey, &value); err != nil {
			// 	log.Fatalf("reading map: %v", err)
			// }
			// log.Printf("%s called %d times\n", fn, value)

			var event Event
			rd, err := perf.NewReader(objs.ExeEvents, os.Getpagesize())
			if err != nil {
				log.Fatal(err)
			}
			defer rd.Close()
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

			fmt.Printf("comm:%s, filename:%s, argv: %s\n", string(event.Comm[:]), string(event.Filename[:]), string(event.Argv[:]))

		case <-stopper:
			panic("return")
			return
		}
	}
}

// func EbpfGather() {
// 	// Name of the kernel function to trace
// 	fn := "sys_execve"

// 	// Subscribe to signals for terminating the program.
// 	stopper := make(chan os.Signal, 1)
// 	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

// 	// Allow the current process to lock memory for eBPF resources.
// 	rrl, err := ebpf.RemoveMemlockRlimit()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Load pre-compiled programs and maps into the kernel.
// 	objs := KProbeExampleObjects{}
// 	if err := LoadKProbeExampleObjects(&objs, nil); err != nil {
// 		log.Fatalf("loading objects: %v", err)
// 	}
// 	defer objs.Close()

// 	// Revert the process' rlimit after eBPF resources have been loaded.
// 	if err := rrl(); err != nil {
// 		log.Fatal(err)
// 	}

// 	// Open a Kprobe at the entry point of the kernel function and attach the
// 	// pre-compiled program. Each time the kernel function enters, the program
// 	// will increment the execution counter by 1. The read loop below polls this
// 	// map value once per second.
// 	kp, err := link.Kprobe(fn, objs.BpfSysExecve)
// 	if err != nil {
// 		log.Fatalf("opening kprobe: %s", err)
// 	}
// 	defer kp.Close()

// 	// Read loop reporting the total amount of times the kernel
// 	// function was entered, once per second.
// 	ticker := time.NewTicker(1 * time.Millisecond)
// 	defer ticker.Stop()

// 	// 一个reader
// 	rd, err := perf.NewReader(objs.ExecveEvents, os.Getpagesize())
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer rd.Close()

// 	log.Println("Waiting for events..")

// 	for {
// 		select {
// 		case <-ticker.C:
// 			var event Event
// 			record, err := rd.Read()
// 			if err != nil {
// 				if perf.IsClosed(err) {
// 					return
// 				}
// 				log.Printf("reading from perf event reader: %s", err)
// 			}

// 			if record.LostSamples != 0 {
// 				log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
// 				continue
// 			}

// 			// Parse the perf event entry into an Event structure.
// 			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
// 				log.Printf("parsing perf event: %s", err)
// 				continue
// 			}

// 			if strings.Contains(unix.ByteSliceToString(event.Comm[:]), "cpuUsage.sh") {
// 				continue
// 			} else if unix.ByteSliceToString(event.Comm[:]) == "node" {
// 				continue
// 			} else if unix.ByteSliceToString(event.Comm[:]) == "watchdog.sh" {
// 				continue
// 			} else if unix.ByteSliceToString(event.Comm[:]) != "bash" {
// 				continue
// 			}
// 			process, err := EventToProcess(event)
// 			if err != nil {
// 				process.Reset()
// 				structs.ProcessPool.Put(process)
// 				continue
// 			}
// 			if config.WhiteListCheck(process) {
// 				process.Reset()
// 				structs.ProcessPool.Put(process)
// 				continue
// 			}

// 			global.ProcessCmdlineCache.Add(process.PID, process.Cmdline)
// 			if ppid, ok := global.ProcessCache.Get(process.PID); ok {
// 				process.PPID = int(ppid.(uint32))
// 			}

// 			process.PidTree = global.GetPstree(uint32(process.PID))
// 			data, err := json.Marshal(process)
// 			if err == nil {
// 				rawdata := make(map[string]string)
// 				rawdata["data"] = string(data)
// 				rawdata["time"] = strconv.Itoa(int(global.Time))
// 				rawdata["data_type"] = "1009"
// 				global.UploadChannel <- rawdata
// 			}
// 			process.Reset()
// 			structs.ProcessPool.Put(process)

// 		case <-stopper:
// 			log.Fatal("goodbye")
// 			return
// 		}
// 	}
// }

// type Event struct {
// 	PID       uint32
// 	UID       uint32
// 	GID       uint32
// 	PPID      uint32
// 	File_name [128]byte
// 	Comm      [16]byte
// 	Argv      [128]byte
// }

// func EventToProcess(event Event) (structs.Process, error) {
// 	proc := structs.ProcessPool.Get().(structs.Process)
// 	proc.PID = int(event.PID)
// 	proc.Cmdline = unix.ByteSliceToString(event.Argv[:])
// 	proc.PPID = int(event.PPID)
// 	proc.UID = fmt.Sprint(event.UID)

// 	process, err := procfs.NewProc(proc.PID)
// 	if err != nil {
// 		return proc, errors.New("no process found")
// 	}

// 	proc.Name = unix.ByteSliceToString(event.Comm[:])

// 	status, err := process.NewStatus()
// 	if err == nil {
// 		proc.EUID = status.UIDs[1]
// 	}

// 	state, err := process.Stat()
// 	if err == nil {
// 		// ebpf 问题，为 0 在用户态补齐
// 		if proc.PPID == 0 {
// 			proc.PPID = state.PPID
// 		}
// 		proc.Session = state.Session
// 		proc.TTY = state.TTY
// 		proc.StartTime = uint64(global.Time)
// 	}

// 	proc.Cwd, err = process.Cwd()
// 	proc.Exe = unix.ByteSliceToString(event.File_name[:])
// 	proc.Sha256, _ = utils.GetSha256ByPath(proc.Exe)

// 	username, ok := global.UsernameCache.Load(proc.UID)
// 	if ok {
// 		proc.Username = username.(string)
// 	} else {
// 		u, err := user.LookupId(proc.UID)
// 		if err == nil {
// 			proc.Username = u.Username
// 			global.UsernameCache.Store(proc.UID, u.Username)
// 		}
// 	}

// 	eusername, ok := global.UsernameCache.Load(proc.EUID)
// 	if ok {
// 		proc.Eusername = eusername.(string)
// 	} else {
// 		eu, err := user.LookupId(proc.EUID)
// 		if err == nil {
// 			proc.Eusername = eu.Username
// 			if euid, err := strconv.Atoi(proc.EUID); err == nil {
// 				global.UsernameCache.Store(euid, eu.Username)
// 			}
// 		}
// 	}

// 	/*
// 		socket 重新hook, 这里临时方案
// 	*/
// 	inodes := make(map[uint32]string)
// 	if sockets, err := network.ParseProcNet(unix.AF_INET, unix.IPPROTO_TCP, "/proc/"+fmt.Sprint(proc.PID)+"/net/tcp"); err == nil {
// 		for _, socket := range sockets {
// 			if socket.Inode != 0 {
// 				if socket.DIP.String() == "0.0.0.0" {
// 					continue
// 				}
// 				inodes[socket.Inode] = string(socket.DIP.String()) + ":" + fmt.Sprint(socket.DPort)
// 			}
// 		}
// 	}

// 	fds, _ := process.FileDescriptorTargets()
// 	for _, fd := range fds {
// 		if strings.HasPrefix(fd, "socket:[") {
// 			inode, _ := strconv.ParseUint(strings.TrimRight(fd[8:], "]"), 10, 32)
// 			d, ok := inodes[uint32(inode)]
// 			if ok {
// 				if proc.RemoteAddrs == "" {
// 					proc.RemoteAddrs = d
// 				} else if strings.Contains(proc.RemoteAddrs, d) {
// 					continue
// 				}
// 				proc.RemoteAddrs = proc.RemoteAddrs + "," + d
// 			}
// 		}
// 	}

// 	return proc, nil
// }
