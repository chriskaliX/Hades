package ebpf

import (
	"agent/collector/common"
	"agent/global"
	"agent/global/structs"
	"agent/utils"
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"go.uber.org/zap"
)

// EBPFProbe
type TracerProbe struct {
	EBPFProbe
}

// 重写 Init
func (t *TracerProbe) Init(ctx context.Context) error {
	t.EBPFProbe.Init(ctx)
	t.probeObject = &TracerObject{
		links: make([]link.Link, 0),
	}
	t.probeBytes = TracerProgByte
	return nil
}

// --- Objects ---
// 对象, 用于映射
type TracerObject struct {
	TracerProgs
	TracerMaps
	links []link.Link
}

func (t *TracerObject) AttachProbe() error {
	forkLink, err := link.Tracepoint("sched", "sched_process_fork", t.TracerProgs.TracepointFork)
	if err != nil {
		zap.S().Error(err)
		return err
	}
	t.links = append(t.links, forkLink)
	execveLink, err := link.Tracepoint("syscalls", "sys_enter_execve", t.TracerProgs.TracepointExecve)
	if err != nil {
		zap.S().Error(err)
		return err
	}
	t.links = append(t.links, execveLink)
	execveatLink, err := link.Tracepoint("syscalls", "sys_enter_execveat", t.TracerProgs.TracepointExecveat)
	if err != nil {
		zap.S().Error(err)
		return err
	}
	t.links = append(t.links, execveatLink)
	return nil
}

func (t *TracerObject) Read() error {
	rd, err := perf.NewReader(t.TracerMaps.Perfevents, 4*os.Getpagesize())
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
	var lastttyname string
	var lastcwd string

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return err
			}
			zap.S().Info(fmt.Sprintf("reading from perf event reader: %s", err))
			continue
		}

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

		if pid == 0 {
			pid = event.Pid
		}

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
			lastttyname = string(bytes.Trim(event.TTYName[:], "\x00"))
			lastcwd = string(bytes.Trim(event.Cwd[:], "\x00"))
			// TODO: 好好看一下这个问题, 暂时先当没有来写（或者拼接部分我们在 eBPF 中做? 看一下）
		} else {
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
				lastttyname = string(bytes.Trim(event.TTYName[:], "\x00"))
				lastcwd = string(bytes.Trim(event.Cwd[:], "\x00"))
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
			process.TTYName = lastttyname
			process.Cwd = lastcwd

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

// TODO: 逻辑有点问题
func (t *TracerObject) Close() error {
	for _, link := range t.links {
		if err := link.Close(); err != nil {
			return err
		}
	}
	return nil
}

// 程序对应函数名
type TracerProgs struct {
	TracepointExecve   *ebpf.Program `ebpf:"enter_execve"`
	TracepointExecveat *ebpf.Program `ebpf:"enter_execveat"`
	TracepointFork     *ebpf.Program `ebpf:"process_fork"`
}

// 对应 reader 函数名
type TracerMaps struct {
	Perfevents *ebpf.Map `ebpf:"perf_events"`
}

//go:embed tracer/tracer.o
var TracerProgByte []byte

type enter_execve_t struct {
	Ts       uint64
	Pns      uint64
	Cid      uint64
	Type     uint32
	Pid      uint32
	Tid      uint32
	Uid      uint32
	Gid      uint32
	Ppid     uint32
	Argsize  uint32
	Filename [32]byte
	Comm     [16]byte
	PComm    [16]byte
	Args     [128]byte
	Nodename [65]byte
	TTYName  [64]byte
	Cwd      [40]byte
}

func formatByte(b []byte) string {
	return string(bytes.ReplaceAll((bytes.Trim(b[:], "\x00")), []byte("\x00"), []byte(" ")))
}
