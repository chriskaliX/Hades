package pool

import (
	"agent/proto"
	"sync"
)

var (
	recordPool = sync.Pool{
		New: func() interface{} {
			return &proto.EncodedRecord{
				Data: make([]byte, 0, 1024*2),
			}
		},
	}
)

func Get() *proto.EncodedRecord {
	return recordPool.Get().(*proto.EncodedRecord)
}

func Put(rec *proto.EncodedRecord) {
	recordPool.Put(rec)
}
