package decoder

import (
	"hades-ebpf/user/cache"

	"github.com/bytedance/sonic"
	"github.com/shirou/gopsutil/host"
)

var bootTime = uint64(0)

// Context contains the kern space struct data_context and the
// user space extra field from the path
type Context struct {
	StartTime uint64  `json:"starttime"` // elasped since system boot in nanoseconds
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

func (c *Context) MarshalJson() ([]byte, error) { return sonic.Marshal(c) }

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

func init() {
	bootTime, _ = host.BootTime()
}
