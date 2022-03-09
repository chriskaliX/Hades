package userspace

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"hades-ebpf/userspace/cache"
	"hades-ebpf/userspace/decoder"
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
// @issue2: json.Marshal use reflect
// @issue3: Add a map to simplify the switch (regist to the map)
func (t *HadesObject) Read() error {
	var (
		reader *perf.Reader
		err    error
		record perf.Record
	)
	if reader, err = perf.NewReader(t.HadesMaps.Perfevents, 4*os.Getpagesize()); err != nil {
		zap.S().Error(err.Error())
		return err
	}
	defer reader.Close()
	rawdata := make(map[string]string, 1)
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
			rawdata["data"] = fmt.Sprintf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			rawdata["data_type"] = "999"
			zap.S().Info(fmt.Sprintf("perf event ring buffer full, dropped %d samples", record.LostSamples))
			continue
		}

		// init the buffer
		decoder.DefaultDecoder.SetBuffer(record.RawSample)
		ctx, err := decoder.DefaultDecoder.DecodeContext()
		if err != nil {
			decoder.PutContext(ctx)
			continue
		}
		switch ctx.Type {
		case TRACEPOINT_SYSCALLS_EXECVE:
			err = parser.DefaultExecve.Parse()
			if err == nil {
				ctx.SetEvent(parser.DefaultExecve)
			}
		case TRACEPOINT_SYSCALLS_EXECVEAT:
			err = parser.DefaultExecveAt.Parse()
			if err == nil {
				ctx.SetEvent(parser.DefaultExecveAt)
			}

		case KRPOBE_SECURITY_BPRM_CHECK:
			// process.Syscall = "security_bprm_check"
			// if file, err := parseStr(buffers); err == nil {
			// 	process.Exe = file
			// }
		case TRACEPOINT_SYSCALLS_PRCTL:
			err = parser.DefaultPrctl.Parse()
			if err == nil {
				ctx.SetEvent(parser.DefaultPrctl)
			}
		case TRACEPOINT_SYSCALLS_PTRACE:
			err = parser.DefaultPtrace.Parse()
			if err == nil {
				ctx.SetEvent(parser.DefaultPtrace)
			}
		case 9:
			err = parser.DefaultSockConn.Parse()
			if err == nil {
				ctx.SetEvent(parser.DefaultSockConn)
			}
		case 10:
			err = parser.DefaultSockBind.Parse()
			if err == nil {
				ctx.SetEvent(parser.DefaultSockBind)
			}
		case 11:
			// process.Syscall = "commit_creds"
			// parser.CommitCreds(buffers, process)
		}

		ctx.Sha256, _ = share.GetFileHash(ctx.Exe)
		ctx.Username = cache.GetUsername(strconv.Itoa(int(ctx.Uid)))
		ctx.StartTime = uint64(share.Time)
		if data, err := json.Marshal(ctx); err == nil {
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
		decoder.PutContext(ctx)
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
