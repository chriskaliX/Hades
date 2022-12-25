package decoder

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hades-ebpf/user/cache"

	"github.com/bytedance/sonic"
)

// Context contains the kern space struct data_context and the
// user space extra field from the path
type Context struct {
	Starttime uint64  `json:"starttime"` // elasped since system boot in nanoseconds
	CgroupID  uint64  `json:"cgroupid"`
	Pns       uint32  `json:"pns"`  // pid namespace
	Type      uint32  `json:"type"` // Type returns the type of the syscall
	Pid       uint32  `json:"pid"`
	Tid       uint32  `json:"tid"`
	Uid       uint32  `json:"uid"`
	Gid       uint32  `json:"gid"`
	Ppid      uint32  `json:"ppid"` // Ppid is the parent pid of the event
	Pgid      uint32  `json:"pgid"` // Pgid is the process group id
	SessionID uint32  `json:"sessionid"`
	Comm      string  `json:"comm"`     // Comm is the task->comm
	PComm     string  `json:"pcomm"`    // PComm is the parent task->comm
	Nodename  string  `json:"nodename"` // Nodename is the uts namespace nodename
	RetVal    int64   `json:"retval"`   // Retval is the return value of the syscall
	Argnum    uint8   `json:"-"`
	_         [3]byte `json:"-"` // Padding field for memory align
	// Extra context value from event and user space
	ExeHash  string `json:"exe_hash"`
	Username string `json:"username"`
	Exe      string `json:"exe"`
	Syscall  string `json:"syscall"`
	PpidArgv string `json:"ppid_argv"`
	PgidArgv string `json:"pgid_argv"`
	PodName  string `json:"pod_name"`
}

// GetSizeBytes returns the bytes of the context in kern space
// and padding of the struct is also included.
func (Context) GetSizeBytes() int { return 168 }

func (ctx *Context) DecodeContext(decoder *EbpfDecoder) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < ctx.GetSizeBytes() {
		return fmt.Errorf("can't read context from buffer: buffer too short")
	}
	ctx.Starttime = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+8])
	ctx.CgroupID = binary.LittleEndian.Uint64(decoder.buffer[offset+8 : offset+16])
	ctx.Pns = binary.LittleEndian.Uint32(decoder.buffer[offset+16 : offset+20])
	ctx.Type = binary.LittleEndian.Uint32(decoder.buffer[offset+20 : offset+24])
	ctx.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+24 : offset+28])
	ctx.Tid = binary.LittleEndian.Uint32(decoder.buffer[offset+28 : offset+32])
	ctx.Uid = binary.LittleEndian.Uint32(decoder.buffer[offset+32 : offset+36])
	ctx.Gid = binary.LittleEndian.Uint32(decoder.buffer[offset+36 : offset+40])
	ctx.Ppid = binary.LittleEndian.Uint32(decoder.buffer[offset+40 : offset+44])
	ctx.Pgid = binary.LittleEndian.Uint32(decoder.buffer[offset+44 : offset+48])
	ctx.SessionID = binary.LittleEndian.Uint32(decoder.buffer[offset+48 : offset+52])
	ctx.Comm = string(bytes.TrimRight(decoder.buffer[offset+52:offset+68], "\x00"))
	ctx.PComm = string(bytes.TrimRight(decoder.buffer[offset+68:offset+84], "\x00"))
	ctx.Nodename = string(bytes.Trim(decoder.buffer[offset+84:offset+148], "\x00"))
	ctx.RetVal = int64(binary.LittleEndian.Uint64(decoder.buffer[offset+152 : offset+160]))
	ctx.Argnum = uint8(binary.LittleEndian.Uint16(decoder.buffer[offset+160 : offset+168]))
	decoder.cursor += ctx.GetSizeBytes()
	return nil
}

// FillContext get some extra field from Event and userspace caches
func (c *Context) FillContext(name, exe string) {
	c.Syscall = name
	c.Exe = exe
	c.PpidArgv = cache.DefaultArgvCache.Get(c.Ppid)
	c.PgidArgv = cache.DefaultArgvCache.Get(c.Pgid)
	c.PodName = cache.DefaultNsCache.Get(c.Pid, c.Pns)
	c.Username = cache.DefaultUserCache.Get(c.Uid)
	c.ExeHash = cache.DefaultHashCache.GetHash(c.Exe)
}

func (c *Context) MarshalJson() ([]byte, error) {
	return sonic.Marshal(c)
}

type SlimCred struct {
	Uid   uint32 /* real UID of the task */
	Gid   uint32 /* real GID of the task */
	Suid  uint32 /* saved UID of the task */
	Sgid  uint32 /* saved GID of the task */
	Euid  uint32 /* effective UID of the task */
	Egid  uint32 /* effective GID of the task */
	Fsuid uint32 /* UID for VFS ops */
	Fsgid uint32 /* GID for VFS ops */
}

func (s SlimCred) GetSizeBytes() uint32 { return 32 }
