package subhandle

import (
	"context"
	"hboat/pkg/basic/mongo"
	"time"

	"go.uber.org/zap"
)

const (
	AgentType  = "agent"
	PluginType = "plugin"
)

type Metric struct {
	model chan interface{} // key: col name, value: model
}

func NewMetric() *Metric {
	return &Metric{
		model: make(chan interface{}, 8*1024),
	}
}

func (w *Metric) Add(model interface{}) {
	select {
	case w.model <- model:
	default:
		zap.S().Errorf("handler_worker_add", "channel is full")
	}
}

func (w *Metric) Deamon() {
	ticker := time.NewTicker(3 * time.Second)
	var writer []interface{}
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
			res, err := mongo.MongoProxyImpl.MetricC.InsertMany(context.Background(), writer, nil)
			if err != nil {
				zap.S().Errorf("handler_worker_bulkwrite", "%s", err.Error())
			} else {
				zap.S().Debugf("handler_worker_bulkwrite", "InsertedCount:%d", len(res.InsertedIDs))
			}
			writer = writer[:0]
		}
		// count oversize, write into mongo
		if len(writer) >= 100 {
			res, err := mongo.MongoProxyImpl.MetricC.InsertMany(context.Background(), writer, nil)
			if err != nil {
				zap.S().Errorf("handler_worker_bulkwrite", "%s", err.Error())
			} else {
				zap.S().Debugf("handler_worker_bulkwrite", "InsertedCount:%d", len(res.InsertedIDs))
			}
			writer = writer[:0]
		}
		// keep looping
	}
}
