package decoder

import (
	"hades-ebpf/user/cache"
	"sync"

	"github.com/bytedance/sonic"
)

var contextPool sync.Pool
var slimCredPool sync.Pool

func init() {
	contextPool.New = func() interface{} {
		return &Context{}
	}
	slimCredPool.New = func() interface{} {
		return &SlimCred{}
	}
}

type Context struct {
	Ts        uint64  `json:"timestamp"`
	CgroupID  uint64  `json:"cgroupid"`
	Pns       uint32  `json:"pns"`
	Type      uint32  `json:"type"`
	Pid       uint32  `json:"pid"`
	Tid       uint32  `json:"tid"`
	Uid       uint32  `json:"uid"`
	Gid       uint32  `json:"gid"`
	Ppid      uint32  `json:"ppid"`
	Pgid      uint32  `json:"pgid"`
	Sessionid uint32  `json:"sessionid"`
	Comm      string  `json:"comm"`
	PComm     string  `json:"pcomm"`
	Nodename  string  `json:"nodename"`
	RetVal    uint64  `json:"retval"`
	Argnum    uint8   `json:"-"`
	_         [3]byte `json:"-"`
	// added
	ExeHash   string `json:"exe_hash"`
	Username  string `json:"username"`
	StartTime int64  `json:"starttime"`
	Exe       string `json:"exe"`
	Syscall   string `json:"syscall"`
	PpidArgv  string `json:"ppid_argv"`
	PgidArgv  string `json:"pgid_argv"`
	PodName   string `json:"pod_name"`
	Event     `json:"-"`
}

func (Context) GetSizeBytes() uint32 {
	return 168
}

func (c *Context) FillContext() {
	c.PpidArgv = cache.DefaultArgvCache.Get(c.Ppid)
	c.PgidArgv = cache.DefaultArgvCache.Get(c.Pgid)
	c.ExeHash = cache.DefaultHashCache.Get(c.Exe)
	c.Username = cache.DefaultUserCache.Get(c.Uid)
	c.PodName = cache.DefaultNsCache.Get(c.Pid, c.Pns)
}

// Temp way to do merge or inline...
// Since the inline tag in golang is still invaild now(since 2013 the first issue proposed)
// We have to archieve by this way...
func (c *Context) MarshalJson() (result string, err error) {
	var (
		ctxByte    []byte
		eventByte  []byte
		resultByte []byte
	)
	if ctxByte, err = sonic.Marshal(c); err != nil {
		return
	}
	if eventByte, err = sonic.Marshal(c.Event); err != nil {
		return
	}
	resultByte = append(resultByte, ctxByte[:len(ctxByte)-2]...)
	resultByte = append(resultByte, byte('"'), byte(','))
	resultByte = append(resultByte, eventByte[1:]...)
	result = string(resultByte)
	return
}

func (c *Context) SetEvent(event Event) {
	c.Syscall = event.String()
	c.Exe = event.GetExe()
	c.Event = event
}

func (c *Context) ToString() (s string, err error) {
	return sonic.MarshalString(c)
}

func NewContext() *Context {
	return contextPool.Get().(*Context)
}

func PutContext(data *Context) {
	contextPool.Put(data)
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

func (s SlimCred) GetSizeBytes() uint32 {
	return 32
}

func NewSlimCred() *SlimCred {
	return slimCredPool.Get().(*SlimCred)
}

func PutSlimCred(data *SlimCred) {
	slimCredPool.Put(data)
}
