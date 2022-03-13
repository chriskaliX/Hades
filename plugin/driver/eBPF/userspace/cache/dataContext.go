package cache

import "sync"

var dataContextPool sync.Pool

func init() {
	dataContextPool.New = func() interface{} {
		return &DataContext{}
	}
}

type DataContext struct {
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

func (DataContext) GetSize() uint32 {
	return 168
}

func NewDataContext() *DataContext {
	return dataContextPool.Get().(*DataContext)
}

func PutDataContext(data *DataContext) {
	dataContextPool.Put(data)
}
