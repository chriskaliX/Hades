package decoder

import (
	"hades-ebpf/userspace/helper"
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
	Ts        uint64   `json:"timestamp"`
	CgroupID  uint64   `json:"cgroupid"`
	UtsInum   uint32   `json:"utsinum"`
	Type      uint32   `json:"type"`
	Pid       uint32   `json:"pid"`
	Tid       uint32   `json:"tid"`
	Uid       uint32   `json:"uid"`
	EUid      uint32   `json:"euid"`
	Gid       uint32   `json:"gid"`
	Ppid      uint32   `json:"ppid"`
	Sessionid uint32   `json:"sessionid"`
	Comm      string   `json:"comm"`
	PComm     string   `json:"pomm"`
	Nodename  string   `json:"nodename"`
	RetVal    uint64   `json:"retval"`
	Argnum    uint8    `json:"argnum"`
	_         [11]byte `json:"-"`
	// added
	Sha256    string           `json:"sha256"`
	Username  string           `json:"username"`
	StartTime uint64           `json:"starttime"`
	Exe       string           `json:"exe"`
	Syscall   string           `json:"syscall"`
	Event     `json:",inline"` // inline tag is no longer support which is been discussed for 9 years
}

func (Context) GetSizeBytes() uint32 {
	return 168
}

func (c *Context) SetEvent(event Event) {
	c.Syscall = event.String()
	c.Exe = event.GetExe()
	c.Event = event
}

func (c *Context) ToString() (s string, err error) {
	var _byte []byte
	if _byte, err = share.Marshal(c); err != nil {
		return
	}
	s = helper.ZeroCopyString(_byte)
	return
}

func NewContext() *Context {
	return contextPool.Get().(*Context)
}

func PutContext(data *Context) {
	contextPool.Put(data)
}

// // SlimCred
// type SlimCred struct {
// 	Uid            uint32 /* real UID of the task */
// 	Gid            uint32 /* real GID of the task */
// 	Suid           uint32 /* saved UID of the task */
// 	Sgid           uint32 /* saved GID of the task */
// 	Euid           uint32 /* effective UID of the task */
// 	Egid           uint32 /* effective GID of the task */
// 	Fsuid          uint32 /* UID for VFS ops */
// 	Fsgid          uint32 /* GID for VFS ops */
// 	UserNamespace  uint32 /* User Namespace of the of the event */
// 	SecureBits     uint32 /* SUID-less security management */
// 	CapInheritable uint64 /* caps our children can inherit */
// 	CapPermitted   uint64 /* caps we're permitted */
// 	CapEffective   uint64 /* caps we can actually use */
// 	CapBounding    uint64 /* capability bounding set */
// 	CapAmbient     uint64 /* Ambient capability set */
// }
