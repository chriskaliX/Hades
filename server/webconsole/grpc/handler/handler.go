// Handler handles the event from agent, including parsing, counting, storing
package handler

import (
	"hboat/grpc/handler/subhandle"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

var EventHandler = make(map[int32]Event)
var EventNameCache = make(map[string]Event)

type Event interface {
	ID() int32
	Name() string
	Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error // Handle the data
}

func RegistEvent(e Event) {
	EventHandler[e.ID()] = e
	EventNameCache[e.Name()] = e
}

// As we using package_seq here, packages are streaming instead of packing in one request.
// The way that we using before should be changed for now, the code logic should be like this:
// 1. Create an channel for caching
// 2. Batch write the data into mongo
//
// The data structure in mongodb should be like this
//
//	{
//		"agentid": "xxx",
//		"<name>": "", // should be a set instead of array
//	}
//
// Another thing is that: what if the result should be empty? For example, socket. What if there
// is no socket in the machine, how should we know and clear this? Fix: send an empty packet with
// package_seq, let the server do the clear action.
// We reckon that the worker is the only proper way to operate the databases.
var DefaultWorker = NewWorker()

type Worker struct {
	Asset  *subhandle.Asset
	Metric *subhandle.Metric
}

func NewWorker() *Worker {
	w := &Worker{
		Asset:  subhandle.NewAsset(),
		Metric: subhandle.NewMetric(),
	}
	go w.Asset.Daemon()
	go w.Metric.Deamon()
	return w
}

func (w *Worker) Add(dt int32, agentid string, m map[string]interface{}) {
	w.Asset.Add(dt, agentid, m)
}

func (w *Worker) AddMetric(model interface{}) {
	w.Metric.Add(model)
}
