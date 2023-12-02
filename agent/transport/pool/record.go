package pool

import (
	"github.com/chriskaliX/Hades/agent/proto"
	"sync"

	"github.com/chriskaliX/SDK/transport/protocol"
	"golang.org/x/exp/maps"
)

var recordPool = sync.Pool{
	New: func() interface{} {
		return &proto.Record{
			Data: &proto.Payload{
				Fields: make(map[string]string, 24),
			},
		}
	},
}

func Get() *proto.Record {
	return recordPool.Get().(*proto.Record)
}

func SDKGet() protocol.ProtoType {
	return recordPool.Get().(*proto.Record)
}

func Put(rec *proto.Record) {
	defer recordPool.Put(rec)
	if rec != nil && rec.Data != nil {
		maps.Clear(rec.Data.Fields)
	}
}
