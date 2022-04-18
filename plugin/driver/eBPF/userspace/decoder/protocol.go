package decoder

import (
	"hades-ebpf/userspace/share"
	"sync"

	jsonpatch "github.com/evanphx/json-patch"
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
	Sessionid uint32  `json:"sessionid"`
	Comm      string  `json:"comm"`
	PComm     string  `json:"pcomm"`
	Nodename  string  `json:"nodename"`
	RetVal    uint64  `json:"retval"`
	Argnum    uint8   `json:"-"`
	_         [7]byte `json:"-"`
	// added
	Sha256    string     `json:"sha256"`
	Username  string     `json:"username"`
	StartTime uint64     `json:"starttime"`
	Exe       string     `json:"exe"`
	Syscall   string     `json:"syscall"`
	Event     `json:"-"` // inline tag is no longer support which is been discussed for 9 years
}

func (Context) GetSizeBytes() uint32 {
	return 160
}

// Temp way to do merge or inline...
// Since the inline tag in golang is still invaild now(since 2013 the first issue proposed)
// We have to archieve by this way...
func (c *Context) MarshalJson() (result string, err error) {
	ctxByte, err := share.MarshalBytes(c)
	if err != nil {
		return
	}
	defer ctxByte.Free()
	eventByte, err := share.MarshalBytes(c.Event)
	if err != nil {
		return
	}
	defer eventByte.Free()
	var resultByte []byte
	if resultByte, err = jsonpatch.MergePatch(ctxByte.Bytes(), eventByte.Bytes()); err != nil {
		return
	}
	result = string(resultByte)
	return
}

func (c *Context) SetEvent(event Event) {
	c.Syscall = event.String()
	c.Exe = event.GetExe()
	c.Event = event
}

func (c *Context) ToString() (s string, err error) {
	return share.Marshal(c)
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
