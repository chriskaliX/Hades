package ebpf

import (
	"agent/collector/common"
	"agent/collector/ebpf/userspace/parser"
	"agent/global"
	"agent/global/structs"
	"agent/utils"
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

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
	KprobeCommitCreds           *ebpf.Program `ebpf:"kprobe_commit_creds"`
}

type HadesMaps struct {
	Perfevents *ebpf.Map `ebpf:"exec_events"`
}

//TODO: 动态加载
//go:embed src/hades.o
var HadesProgByte []byte

type eventCtx struct {
	Ts        uint64
	CgroupId  uint64
	Uts_inum  uint32
	Type      uint32
	Pid       uint32
	Tid       uint32
	Uid       uint32
	EUid      uint32
	Gid       uint32
	Ppid      uint32
	Sessionid uint32
	Comm      [16]byte
	PComm     [16]byte
	Nodename  [64]byte
	RetVal    uint64
	Argnum    uint8
	_         [11]byte // padding - 结构体修改后要修改 padding
}

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
	// KprobeDoExit, err := link.Kprobe("do_exit", t.HadesProgs.KprobeDoExit)
	// KprobeSysExitGroup, err := link.Kprobe("sys_exit_group", t.HadesProgs.KprobeSysExitGroup)
	KprobeSecurityBprmCheck, err := link.Kprobe("security_bprm_check", t.HadesProgs.KprobeSecurityBprmCheck)
	PrtclLink, err := link.Tracepoint("syscalls", "sys_enter_prctl", t.HadesProgs.TracepointPrctl)
	PtraceLink, err := link.Tracepoint("syscalls", "sys_enter_ptrace", t.HadesProgs.TracepointPtrace)
	SocketConnectLink, err := link.Kprobe("security_socket_connect", t.HadesProgs.KprobeSecuritySocketConnect)
	SocketBindLink, err := link.Kprobe("security_socket_bind", t.HadesProgs.KprobeSecuritySocketBind)
	KprobeCommitCreds, err := link.Kprobe("commit_creds", t.HadesProgs.KprobeCommitCreds)
	if err != nil {
		zap.S().Error(err)
		return err
	}
	t.links = append(t.links, execveLink, execveatLink, KprobeSecurityBprmCheck, TracePointSchedProcessFork, PrtclLink, PtraceLink, SocketConnectLink, SocketBindLink, KprobeCommitCreds)
	return nil
}

// 现在这里的代码都是 demo, 目标是先跑起来, 所以实现上不优雅
func (t *HadesObject) Read() error {
	var (
		reader  *perf.Reader
		err     error
		ctx     eventCtx
		record  perf.Record
		buffers *bytes.Buffer
	)

	if reader, err = perf.NewReader(t.HadesMaps.Perfevents, 4*os.Getpagesize()); err != nil {
		zap.S().Error(err.Error())
		return err
	}
	defer reader.Close()

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
			rawdata["time"] = strconv.Itoa(int(global.Time))
			rawdata["data_type"] = "999"
			global.UploadChannel <- rawdata
			zap.S().Info(fmt.Sprintf("perf event ring buffer full, dropped %d samples", record.LostSamples))
			continue
		}
		buffers = bytes.NewBuffer(record.RawSample)
		// 先消费 context_t
		if err := binary.Read(buffers, binary.LittleEndian, &ctx); err != nil {
			zap.S().Error(err.Error())
			continue
		}
		rawdata := make(map[string]string)
		rawdata["data_type"] = "1000"
		rawdata["time"] = strconv.Itoa(int(global.Time))
		process := structs.ProcessPool.Get().(structs.Process)
		process.Name = formatByte(ctx.Comm[:])
		process.CgroupId = int(ctx.CgroupId)
		process.UID = strconv.Itoa(int(ctx.Uid))
		process.PID = int(ctx.Pid)
		process.PPID = int(ctx.Ppid)
		process.NodeName = formatByte(ctx.Nodename[:])
		process.TID = int(ctx.Tid)
		process.Source = "ebpf"
		process.PName = formatByte(ctx.PComm[:])
		process.Uts_inum = int(ctx.Uts_inum)
		process.EUID = strconv.Itoa(int(ctx.EUid))
		process.Eusername = global.GetUsername(process.EUID)
		switch int(ctx.Type) {
		case TRACEPOINT_SYSCALLS_EXECVE:
			process.Syscall = "execve"
			parser.Execve(buffers, &process)
		case TRACEPOINT_SYSCALLS_EXECVEAT:
			process.Syscall = "execveat"
			parser.Execve(buffers, &process)
		case KPROBE_DO_EXIT:
			process.RetVal = int(ctx.RetVal)
			process.Syscall = "do_exit"
		case KPROBE_EXIT_GROUP:
			process.RetVal = int(ctx.RetVal)
			process.Syscall = "exit_group"
		case KRPOBE_SECURITY_BPRM_CHECK:
			process.Syscall = "security_bprm_check"
			if file, err := parseStr(buffers); err == nil {
				process.Exe = file
			}
		case TRACEPOINT_SYSCALLS_PRCTL:
			process.Syscall = "prtcl"
			parser.Prctl(buffers, &process)
		case TRACEPOINT_SYSCALLS_PTRACE:
			process.Syscall = "ptrace"
			parser.Ptrace(buffers, &process)
		case 9:
			process.Syscall = "socket_connect"
			parser.Net(buffers, &process)
		case 10:
			process.Syscall = "socket_bind"
			parser.Net(buffers, &process)
		case 11:
			process.Syscall = "commit_creds"
			parser.CommitCreds(buffers, &process)
		}

		// if int(ctx.Type) != 11 {
		// 	continue
		// }

		global.ProcessCmdlineCache.Add(uint32(process.PID), process.Exe)
		global.ProcessCache.Add(uint32(process.PID), uint32(process.PPID))
		process.Sha256, _ = common.GetFileHash(process.Exe)
		process.Username = global.GetUsername(process.UID)
		process.StartTime = uint64(global.Time)
		data, err := utils.Marshal(process)
		if err == nil {
			rawdata["data"] = string(data)
			global.UploadChannel <- rawdata
		}
		process.Reset()
		structs.ProcessPool.Put(process)
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
	return string(bytes.ReplaceAll((bytes.Trim(b[:], "\x00")), []byte("\x00"), []byte(" ")))
}

func parseExecve_(buf io.Reader) (file, args, pids, cwd, tty, stdin, stout, remote_port, remote_addr string, envs []string, err error) {
	// files
	if file, err = parser.ParseStr(buf); err != nil {
		return
	}

	if cwd, err = parser.ParseStr(buf); err != nil {
		return
	}

	if tty, err = parser.ParseStr(buf); err != nil {
		return
	}

	if stdin, err = parser.ParseStr(buf); err != nil {
		return
	}

	if stout, err = parser.ParseStr(buf); err != nil {
		return
	}

	if remote_port, remote_addr, err = parseRemoteAddr(buf); err != nil {
		fmt.Println(err)
		return
	}

	// pid_tree
	pid_tree := make([]string, 0)
	if pid_tree, err = parser.ParsePidTree(buf); err != nil {
		return
	}
	pids = strings.Join(pid_tree, "<")
	// 开始读 argv
	argsArr, err := parser.ParseStrArray(buf)
	if err != nil {
		fmt.Println(err)
		return
	}
	// defer strArrPool.Put(argsArr)
	args = strings.Join(argsArr, " ")
	// 开始读 envs
	if envs, err = parser.ParseStrArray(buf); err != nil {
		return
	}
	return
}
