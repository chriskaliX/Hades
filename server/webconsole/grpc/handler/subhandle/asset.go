package subhandle

import (
	"context"
	"fmt"
	"hboat/pkg/basic/mongo"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"

	m "go.mongodb.org/mongo-driver/mongo"
)

type Asset struct {
	queue chan map[string]interface{} // internal queue for caching the events, the queue is lock-based for now
	cache map[int32]map[string]string // map[int32<data_type>]map[string<agentid>]string<seq>
}

func NewAsset() *Asset {
	return &Asset{
		queue: make(chan map[string]interface{}, 512*1024),
		cache: make(map[int32]map[string]string),
	}
}

func (w *Asset) Add(dt int32, agentid string, m map[string]interface{}) {
	m["data_type"] = dt
	m["agent_id"] = agentid
	select {
	case w.queue <- m:
	default:
		zap.S().Errorf("handler_worker_add", "channel is full, dt: %d, agentid: %s is dropped", dt, agentid)
	}
}

func (w *Asset) Daemon() {
	ticker := time.NewTicker(3 * time.Second)
	// for assets col
	var writer []m.WriteModel
	// for ssh col
	var sshWriter []m.WriteModel
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	defer ticker.Stop()
	// For select, let the ticker work
	for {
	Loop:
		select {
		case event := <-w.queue:
			// collector - period
			if package_seq, ok := event["package_seq"]; ok {
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
					var package_seq_str string
					switch v := package_seq.(type) {
					case float64:
						package_seq_str = fmt.Sprintf("%d", int(v))
					case string:
						package_seq_str = v
					default:
						goto Loop
					}
					_, err := mongo.MongoProxyImpl.AssetC.DeleteMany(
						context.Background(),
						bson.M{"agent_id": agentid, "data_type": dt, "package_seq": bson.M{"$ne": package_seq_str}},
					)
					if err != nil {
						zap.S().Errorf("handler_worker_deletemany", "%s", err.Error())
					}
					// update the seq
					w.cache[dt][agentid] = package_seq_str
				}
				// insert
				event["update_time"] = time.Now().Unix() // TODO: to clock, performance
				model := m.NewInsertOneModel().SetDocument(event)
				writer = append(writer, model)
			} else {
				// other events
				temp, ok := event["data_type"]
				if !ok {
					continue
				}
				dataType, ok := temp.(int64)
				if !ok {
					continue
				}
				switch dataType {
				// ssh log
				case 3003:
					event["timestamp"] = time.Now()
					model := m.NewInsertOneModel().SetDocument(event)
					sshWriter = append(sshWriter, model)
				}
			}
		case <-ticker.C:
			if len(writer) > 0 {
				res, err := mongo.MongoProxyImpl.AssetC.BulkWrite(context.Background(), writer, writeOption)
				if err != nil {
					zap.S().Errorf("handler_worker_bulkwrite", "%s", err.Error())
				} else {
					zap.S().Debugf("handler_worker_bulkwrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
				}
				writer = writer[:0]
			}
			if len(sshWriter) > 0 {
				res, err := mongo.MongoProxyImpl.SshC.BulkWrite(context.Background(), sshWriter, writeOption)
				if err != nil {
					zap.S().Errorf("handler_worker_bulkwrite", "%s", err.Error())
				} else {
					zap.S().Debugf("handler_worker_bulkwrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
				}
				sshWriter = sshWriter[:0]
			}
		}
		// count oversize, write into mongo
		if len(writer) >= 100 {
			res, err := mongo.MongoProxyImpl.AssetC.BulkWrite(context.Background(), writer, writeOption)
			if err != nil {
				zap.S().Errorf("handler_worker_bulkwrite", "%s", err.Error())
			} else {
				zap.S().Debugf("handler_worker_bulkwrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}
			writer = writer[:0]
		}
		if len(sshWriter) >= 100 {
			res, err := mongo.MongoProxyImpl.SshC.BulkWrite(context.Background(), sshWriter, writeOption)
			if err != nil {
				zap.S().Errorf("handler_worker_bulkwrite", "%s", err.Error())
			} else {
				zap.S().Debugf("handler_worker_bulkwrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}
			sshWriter = sshWriter[:0]
		}
		// keep looping
	}
}
