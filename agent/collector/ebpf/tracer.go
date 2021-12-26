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
	// execveatLink, err := link.Tracepoint("syscalls", "sys_enter_execveat", t.TracerProgs.TracepointExecveat)
	// if err != nil {
	// 	zap.S().Error(err)
	// 	return err
	// }
	// t.links = append(t.links, execveatLink)
	return nil
}

func (t *TracerObject) Read() error {
	rd, err := perf.NewReader(t.TracerMaps.Perfevents, 8*os.Getpagesize())
	if err != nil {
		zap.S().Error(err.Error())
		return err
	}
	defer rd.Close()

	var ctx ctx

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

		var buffers = bytes.NewBuffer(record.RawSample)

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
		// process.Exe = formatByte(ctx.Exe[:])
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
		// 再消费
		// index 暂时不区分
		file, argv, envp := parseExecve(buffers)
		process.Exe = file
		process.Cwd = ""
		process.LD_Preload = envp

		// 目前只包含了, envp 的信息, 后面会改的
		// if len(ssh) > 0 {
		// 	sshlist := strings.Split(ssh, " ")
		// 	if len(sshlist) == 4 {
		// 		process.RemoteAddr = sshlist[0] + ":" + sshlist[1]
		// 		process.LocalAddr = sshlist[2] + ":" + sshlist[3]
		// 	}
		// }

		// type 添加
		switch int(ctx.Type) {
		case TRACEPOINT_SYSCALLS_EXECVE:
			process.Syscall = "execve"
		}

		global.ProcessCmdlineCache.Add(uint32(process.PID), process.Exe)
		global.ProcessCache.Add(uint32(process.PID), uint32(process.PPID))

		process.Cmdline = argv
		process.PidTree = global.GetPstree(uint32(process.PID))
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
	TracepointExecve *ebpf.Program `ebpf:"enter_execve"`
	// TracepointExecveat *ebpf.Program `ebpf:"enter_execveat"`
	TracepointFork *ebpf.Program `ebpf:"process_fork"`
}

// 对应 reader 函数名
type TracerMaps struct {
	Perfevents *ebpf.Map `ebpf:"exec_events"`
}

//go:embed tracer/tracer.o
var TracerProgByte []byte

type ctx struct {
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
	Nodename        [65]byte
	TTYName         [64]byte
	Argnum          uint8
	_               [6]byte // padding - 结构体修改后要修改 padding
}

func formatByte(b []byte) string {
	return string(bytes.ReplaceAll((bytes.Trim(b[:], "\x00")), []byte("\x00"), []byte(" ")))
}

// 详细拆分, envp 只取 SSH_CONNECTION LD_PRELOAD PWD
func parseExecve(buf io.Reader) (file, args, envp string) {
	envs := make([]string, 2)

	var index uint8
	err := binary.Read(buf, binary.LittleEndian, &index)
	if err != nil {
		return
	}
	var fnamesize uint32
	err = binary.Read(buf, binary.LittleEndian, &fnamesize)
	if fnamesize > 512 {
		return
	}
	filebyte := make([]byte, fnamesize-1)
	err = binary.Read(buf, binary.LittleEndian, &filebyte)
	file = string(filebyte)

	var dummy int8
	binary.Read(buf, binary.LittleEndian, &dummy)

	// 开始读 argv
	// 读 index
	err = binary.Read(buf, binary.LittleEndian, &index)
	// 读 size
	var size uint8
	err = binary.Read(buf, binary.LittleEndian, &size)
	if err != nil {
		zap.S().Error(err.Error())
		return
	}
	argv := make([]string, 0)
	for i := 0; i < int(size); i++ {
		var strsize uint32
		if err = binary.Read(buf, binary.LittleEndian, &strsize); err == nil {
			if strsize > 512 {
				break
			}
			res := make([]byte, strsize-1)
			if err = binary.Read(buf, binary.LittleEndian, &res); err == nil {
				argv = append(argv, string(res))
				// 结尾 drop
				var dummy int8
				binary.Read(buf, binary.LittleEndian, &dummy)
			} else {
				zap.S().Error(err.Error())
				break
			}
		} else {
			zap.S().Error(err.Error())
			break
		}
	}
	args = strings.Join(argv, " ")

	// 开始读 argv
	// 读 index
	err = binary.Read(buf, binary.LittleEndian, &index)
	// 读 size
	err = binary.Read(buf, binary.LittleEndian, &size)
	if err != nil {
		zap.S().Error(err.Error())
		return
	}
	// envs := make([]string, 0)
	for i := 0; i < int(size); i++ {
		var strsize uint32
		if err = binary.Read(buf, binary.LittleEndian, &strsize); err == nil {
			if strsize > 512 {
				break
			}
			res := make([]byte, strsize-1)
			if err = binary.Read(buf, binary.LittleEndian, &res); err == nil {
				resstr := string(res)
				// http://www.wenqujingdian.com/Public/editor/attached/file/20180425/20180425140836_60902.pdf
				// if strings.HasPrefix(resstr, "SSH_CONNECTION=") {
				// 	ssh = strings.Trim(resstr, "SSH_CONNECTION=")
				// } else if strings.HasPrefix(resstr, "LD_PRELOAD=") {
				// 	ld = strings.Trim(resstr, "LD_PRELOAD=")
				// } else if strings.HasPrefix(resstr, "PWD=") {
				// 	pwd = strings.Trim(resstr, "PWD=")
				// }
				envs = append(envs, resstr)

				// 结尾 drop
				var dummy int8
				binary.Read(buf, binary.LittleEndian, &dummy)
			} else {
				zap.S().Error(err.Error())
				break
			}
		} else {
			zap.S().Error(err.Error())
			break
		}
	}
	envp = strings.Join(envs, " ")

	return
}
