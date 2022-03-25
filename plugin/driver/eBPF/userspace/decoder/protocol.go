package decoder

import (
	"hades-ebpf/userspace/share"
	"sync"
)

var contextPool sync.Pool

func init() {
	contextPool.New = func() interface{} {
		return &Context{}
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
	PComm     string  `json:"pomm"`
	Nodename  string  `json:"nodename"`
	RetVal    uint64  `json:"retval"`
	Argnum    uint8   `json:"-"`
	_         [7]byte `json:"-"`
	// added
	Sha256    string            `json:"sha256"`
	Username  string            `json:"username"`
	StartTime uint64            `json:"starttime"`
	Exe       string            `json:"exe"`
	Syscall   string            `json:"syscall"`
	Event     `json:"-,inline"` // inline tag is no longer support which is been discussed for 9 years
}

func (Context) GetSizeBytes() uint32 {
	return 160
}

// Temp way to do merge or inline...
// func (c *Context) MarshalJson() (result []byte, err error) {
// 	ctxByte, err := share.Marshal(c)
// 	if err != nil {
// 		return
// 	}
// 	eventByte, err := share.Marshal(c.Event)
// 	if err != nil {
// 		return
// 	}
// 	return jsonpatch.MergePatch(ctxByte, eventByte)
// }

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
