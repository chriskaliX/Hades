package metrics

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

var Metrics = make(map[string]IMetric)

type IMetric interface {
	Name() string
	Flush(time.Time)
	Init() bool // Is init run needed
}

// internal add metric function
func addMetric(m IMetric) {
	Metrics[m.Name()] = m
	if m.Init() {
		m.Flush(time.Now())
	}
}

// exported Startup function
func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	zap.S().Info("metrics daemon startup")
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			for _, v := range Metrics {
				v.Flush(t)
			}
		}
	}
}
