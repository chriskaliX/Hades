package subhandle

import (
	"context"
	"hboat/pkg/basic/mongo"
	"time"

	m "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

const (
	AgentType  = "agent"
	PluginType = "plugin"
)

type Metric struct {
	model chan *m.InsertOneModel // key: col name, value: model
}

func NewMetric() *Metric {
	return &Metric{
		model: make(chan *m.InsertOneModel, 8*1024),
	}
}

func (w *Metric) Add(model *m.InsertOneModel) {
	select {
	case w.model <- model:
	default:
		zap.S().Errorf("handler_worker_add", "channel is full")
	}
}

func (w *Metric) Deamon() {
	ticker := time.NewTicker(3 * time.Second)
	var writer []m.WriteModel
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	defer ticker.Stop()
	// For select, let the ticker work
	for {
		select {
		case model := <-w.model:
			writer = append(writer, model)
		case <-ticker.C:
			if len(writer) == 0 {
				continue
			}
			res, err := mongo.MongoProxyImpl.MetricC.BulkWrite(context.Background(), writer, writeOption)
			if err != nil {
				zap.S().Errorf("handler_worker_bulkwrite", "%s", err.Error())
			} else {
				zap.S().Debugf("handler_worker_bulkwrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}
			writer = writer[:0]
		}
		// count oversize, write into mongo
		if len(writer) >= 100 {
			res, err := mongo.MongoProxyImpl.MetricC.BulkWrite(context.Background(), writer, writeOption)
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
