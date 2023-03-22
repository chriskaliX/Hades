// Handler handles the event from agent, including parsing, counting, storing
package handler

import (
	"context"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"hboat/pkg/basic/mongo"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"

	m "go.mongodb.org/mongo-driver/mongo"
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
// {
//	"agentid": "xxx",
//	"<name>": "", // should be a set instead of array
// }
//
// Another thing is that: what if the result should be empty? For example, socket. What if there
// is no socket in the machine, how should we know and clear this? Fix: send an empty packet with
// package_seq, let the server do the clear action.
// We reckon that the worker is the only proper way to operate the databases.
var DefaultWorker = NewWorker()

type Worker struct {
	queue chan map[string]interface{} // internal queue for caching the events, the queue is lock-based for now
	cache map[int32]map[string]string // map[int32<data_type>]map[string<agentid>]string<seq>
}

func NewWorker() *Worker {
	w := &Worker{
		queue: make(chan map[string]interface{}, 512*1024),
		cache: make(map[int32]map[string]string),
	}
	go w.Run()
	return w
}

func (w *Worker) Add(dt int32, agentid string, m map[string]interface{}) {
	m["data_type"] = dt
	m["agent_id"] = agentid
	select {
	case w.queue <- m:
	default:
		zap.S().Errorf("handler_worker_add", "channel is full, dt: %d, agentid: %s is dropped", dt, agentid)
	}
}

func (w *Worker) Run() {
	ticker := time.NewTicker(3 * time.Second)
	var writer []m.WriteModel
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	defer ticker.Stop()
	// For select, let the ticker work
	for {
		select {
		case event := <-w.queue:
			// get needed data
			package_seq, ok := event["package_seq"]
			if !ok {
				continue
			}
			dt := event["data_type"].(int32)
			agentid := event["agent_id"].(string)
			// cache empty check
			if _, ok := w.cache[dt]; !ok {
				w.cache[dt] = make(map[string]string)
			}
			// seq check
			if w.cache[dt][agentid] != package_seq {
				// seq is not the same, clear the same seq
				// In Hades, the data_type is also needed
				_, err := mongo.AssetC.DeleteMany(
					context.Background(),
					bson.M{"agent_id": agentid, "data_type": dt, "package_seq": bson.M{"$ne": package_seq.(string)}},
				)
				if err != nil {
					zap.S().Errorf("handler_worker_deletemany", "%s", err.Error())
				}
				// update the seq
				w.cache[dt][agentid] = package_seq.(string)
			}
			// insert
			event["update_time"] = time.Now().Unix() // TODO: to clock, performance
			model := m.NewInsertOneModel().SetDocument(event)
			writer = append(writer, model)
		case <-ticker.C:
			if len(writer) == 0 {
				continue
			}
			res, err := mongo.AssetC.BulkWrite(context.Background(), writer, writeOption)
			if err != nil {
				zap.S().Errorf("handler_worker_bulkwrite", "%s", err.Error())
			} else {
				zap.S().Debugf("handler_worker_bulkwrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}
			writer = writer[:0]
		}
		// count oversize, write into mongo
		if len(writer) >= 100 {
			res, err := mongo.AssetC.BulkWrite(context.Background(), writer, writeOption)
			if err != nil {
				zap.S().Errorf("handler_worker_bulkwrite", "%s", err.Error())
			} else {
				zap.S().Debugf("handler_worker_bulkwrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}
			writer = writer[:0]
		}
		// keep looping
	}
}
