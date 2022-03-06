package userspace

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"hades-ebpf/userspace/cache"
	"hades-ebpf/userspace/helper"
	"hades-ebpf/userspace/parser"
	"hades-ebpf/userspace/share"
	"os"
	"strconv"

	"github.com/chriskaliX/plugin"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"go.uber.org/zap"
)

// EBPFProbe
type HadesProbe struct {
	EBPFProbe
}

type HadesObject struct {
	HadesProgs
	HadesMaps
	links []link.Link
}

type HadesProgs struct {
	TracepointExecve            *ebpf.Program `ebpf:"sys_enter_execve"`
	TracepointExecveat          *ebpf.Program `ebpf:"sys_enter_execveat"`
	KprobeDoExit                *ebpf.Program `ebpf:"kprobe_do_exit"`
	KprobeSysExitGroup          *ebpf.Program `ebpf:"kprobe_sys_exit_group"`
	KprobeSecurityBprmCheck     *ebpf.Program `ebpf:"kprobe_security_bprm_check"`
	TracePointSchedProcessFork  *ebpf.Program `ebpf:"tracepoint_sched_process_fork"`
	TracepointPrctl             *ebpf.Program `ebpf:"sys_enter_prctl"`
	TracepointPtrace            *ebpf.Program `ebpf:"sys_enter_ptrace"`
	KprobeSecuritySocketConnect *ebpf.Program `ebpf:"kprobe_security_socket_connect"`
	KprobeSecuritySocketBind    *ebpf.Program `ebpf:"kprobe_security_socket_bind"`
}

type HadesMaps struct {
	Perfevents *ebpf.Map `ebpf:"exec_events"`
}

//go:embed hades_ebpf_driver.o
var HadesProgByte []byte

// 重写 Init
func (t *HadesProbe) Init(ctx context.Context) error {
	t.EBPFProbe.Init(ctx)
	t.probeObject = &HadesObject{
		links: make([]link.Link, 0),
	}
	t.probeBytes = HadesProgByte
	t.opts = &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: 1 * 1024 * 1024, // the size of verifier log !!!
		},
	}
	return nil
}

func (t *HadesObject) AttachProbe() error {
	execveLink, err := link.Tracepoint("syscalls", "sys_enter_execve", t.HadesProgs.TracepointExecve)
	execveatLink, err := link.Tracepoint("syscalls", "sys_enter_execveat", t.HadesProgs.TracepointExecveat)
	TracePointSchedProcessFork, err := link.Tracepoint("sched", "sched_process_fork", t.HadesProgs.TracePointSchedProcessFork)
	KprobeSecurityBprmCheck, err := link.Kprobe("security_bprm_check", t.HadesProgs.KprobeSecurityBprmCheck)
	PrctlLink, err := link.Tracepoint("syscalls", "sys_enter_prctl", t.HadesProgs.TracepointPrctl)
	PtraceLink, err := link.Tracepoint("syscalls", "sys_enter_ptrace", t.HadesProgs.TracepointPtrace)
	SocketConnectLink, err := link.Kprobe("security_socket_connect", t.HadesProgs.KprobeSecuritySocketConnect)
	SocketBindLink, err := link.Kprobe("security_socket_bind", t.HadesProgs.KprobeSecuritySocketBind)
	if err != nil {
		zap.S().Error(err)
		return err
	}
	t.links = append(t.links, execveLink, execveatLink, KprobeSecurityBprmCheck, TracePointSchedProcessFork, PrctlLink, PtraceLink, SocketConnectLink, SocketBindLink)
	return nil
}

// 现在这里的代码都是 demo, 目标是先跑起来, 所以实现上不优雅
// @issue1: binary.Read use reflect
func (t *HadesObject) Read() error {
	var (
		reader  *perf.Reader
		err     error
		dataCtx cache.DataContext
		record  perf.Record
		buffers *bytes.Buffer
	)
	if reader, err = perf.NewReader(t.HadesMaps.Perfevents, 4*os.Getpagesize()); err != nil {
		zap.S().Error(err.Error())
		return err
	}
	defer reader.Close()

	// start to consume the eBPF msg
	for {
		// read first
		if record, err = reader.Read(); err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return err
			}
			zap.S().Info(fmt.Sprintf("reading from perf event reader: %s", err))
			continue
		}
		// think about samples
		if record.LostSamples != 0 {
			rawdata := make(map[string]string)
			rawdata["data"] = fmt.Sprintf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			rawdata["data_type"] = "999"
			zap.S().Info(fmt.Sprintf("perf event ring buffer full, dropped %d samples", record.LostSamples))
			continue
		}

		buffers = bytes.NewBuffer(record.RawSample)
		// consume data context firstly
		if err := binary.Read(buffers, binary.LittleEndian, &dataCtx); err != nil {
			zap.S().Error(err.Error())
			continue
		}

		rawdata := make(map[string]string, 1)
		process := cache.DefaultProcessPool.Get()
		process.CgroupId = dataCtx.CgroupId
		process.UID = strconv.Itoa(int(dataCtx.Uid))
		process.PID = dataCtx.Pid
		process.PPID = dataCtx.Ppid
		process.TID = dataCtx.Tid
		process.Source = "ebpf"
		process.Uts_inum = dataCtx.Uts_inum
		process.EUID = strconv.Itoa(int(dataCtx.EUid))
		process.Eusername = cache.GetUsername(process.EUID)
		process.NodeName = formatByte(dataCtx.Nodename[:])
		process.Name = formatByte(dataCtx.Comm[:])
		process.PName = formatByte(dataCtx.PComm[:])

		switch dataCtx.Type {
		case TRACEPOINT_SYSCALLS_EXECVE:
			process.Syscall = "execve"
			parser.Execve(buffers, process)
		case TRACEPOINT_SYSCALLS_EXECVEAT:
			process.Syscall = "execveat"
			parser.Execve(buffers, process)
		case KPROBE_DO_EXIT:
			process.RetVal = dataCtx.RetVal
			process.Syscall = "do_exit"
		case KPROBE_EXIT_GROUP:
			process.RetVal = dataCtx.RetVal
			process.Syscall = "exit_group"
		case KRPOBE_SECURITY_BPRM_CHECK:
			process.Syscall = "security_bprm_check"
			if file, err := parseStr(buffers); err == nil {
				process.Exe = file
			}
		case TRACEPOINT_SYSCALLS_PRCTL:
			process.Syscall = "prctl"
			parser.Prctl(buffers, process)
		case TRACEPOINT_SYSCALLS_PTRACE:
			process.Syscall = "ptrace"
			err = parser.Ptrace(buffers, process)
			if err != nil {
				os.Stderr.WriteString(err.Error() + "\n")
			}
		case 9:
			process.Syscall = "socket_connect"
			err = parser.Net(buffers, process)
			if err != nil {
				os.Stderr.WriteString(err.Error() + "\n")
			}
		case 10:
			process.Syscall = "socket_bind"
			parser.Net(buffers, process)
		case 11:
			process.Syscall = "commit_creds"
			parser.CommitCreds(buffers, process)
		}
		if dataCtx.Type != TRACEPOINT_SYSCALLS_PTRACE {
			continue
		}
		cache.ProcessCmdlineCache.Add(uint32(process.PID), process.Exe)
		cache.ProcessCache.Add(uint32(process.PID), uint32(process.PPID))
		process.Sha256, _ = share.GetFileHash(process.Exe)
		process.Username = cache.GetUsername(process.UID)
		process.StartTime = uint64(share.Time)
		data, err := share.Marshal(process)
		if err == nil {
			rawdata["data"] = helper.ZeroCopyString(data)
			rec := &plugin.Record{
				DataType:  1000,
				Timestamp: int64(share.Time),
				Data: &plugin.Payload{
					Fields: rawdata,
				},
			}
			share.Client.SendRecord(rec)
		}
		cache.DefaultProcessPool.Put(process)
	}
}

func (t *HadesObject) Close() error {
	for _, link := range t.links {
		if err := link.Close(); err != nil {
			return err
		}
	}
	return nil
}

func formatByte(b []byte) string {
	return helper.ZeroCopyString(bytes.ReplaceAll((bytes.Trim(b[:], "\x00")), []byte("\x00"), []byte(" ")))
}
