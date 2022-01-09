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
	TracepointExecve *ebpf.Program `ebpf:"enter_execve"`
	// TracepointExecveat *ebpf.Program `ebpf:"enter_execveat"`
	// TracepointFork *ebpf.Program `ebpf:"process_fork"`
}

type HadesMaps struct {
	Perfevents *ebpf.Map `ebpf:"exec_events"`
}

//TODO: 动态加载
//go:embed src/hades.o
var HadesProgByte []byte

type eventCtx struct {
	Ts              uint64
	Uts_inum        uint64
	Parent_uts_inum uint64
	CgroupId        uint64
	Type            uint32
	Pid             uint32
	Tid             uint32
	Uid             uint32
	EUid            uint32
	Gid             uint32
	Ppid            uint32
	Sessionid       uint32
	Comm            [16]byte
	PComm           [16]byte
	Nodename        [64]byte
	TTYName         [64]byte
	Argnum          uint8
	_               [7]byte // padding - 结构体修改后要修改 padding
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
	if err != nil {
		zap.S().Error(err)
		return err
	}
	t.links = append(t.links, execveLink)
	return nil
}

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
		process.Parent_uts_inum = int(ctx.Parent_uts_inum)
		process.TTYName = formatByte(ctx.TTYName[:])
		process.EUID = strconv.Itoa(int(ctx.EUid))
		process.Eusername = global.GetUsername(process.EUID)

		file, args, pids, cwd, envs, err := parseExecve_(buffers)
		if err == nil {
			process.Cmdline = args
			process.Exe = file
			// type 添加
			switch int(ctx.Type) {
			case TRACEPOINT_SYSCALLS_EXECVE:
				for _, env := range envs {
					if strings.HasPrefix(env, "SSH_CONNECTION=") {
						process.SSH_connection = strings.TrimLeft(env, "SSH_CONNECTION=")
					} else if strings.HasPrefix(env, "LD_PRELOAD=") {
						process.LD_Preload = strings.TrimLeft(env, "LD_PRELOAD=")
					} else if strings.HasPrefix(env, "LD_LIBRARY_PATH=") {
						process.LD_Library_Path = strings.TrimLeft(env, "LD_LIBRARY_PATH")
					}
				}
			}
		} else {
			zap.S().Error(err.Error())
		}
		process.Cwd = cwd
		global.ProcessCmdlineCache.Add(uint32(process.PID), process.Exe)
		global.ProcessCache.Add(uint32(process.PID), uint32(process.PPID))
		process.PidTree = pids
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

func parseExecve_(buf io.Reader) (file, args, pids, cwd string, envs []string, err error) {
	// files
	if file, err = parseStr(buf); err != nil {
		return
	}
	if cwd, err = parseStr(buf); err != nil {
		return
	}
	// pid_tree
	pid_tree := make([]string, 0)
	if pid_tree, err = parsePidTree(buf); err != nil {
		return
	}
	pids = strings.Join(pid_tree, "<")
	// 开始读 argv
	argsArr, err := parseStrArray(buf)
	if err != nil {
		fmt.Println(err)
		return
	}
	// defer strArrPool.Put(argsArr)
	args = strings.Join(argsArr, " ")
	// 开始读 envs
	if envs, err = parseStrArray(buf); err != nil {
		return
	}
	return
}
