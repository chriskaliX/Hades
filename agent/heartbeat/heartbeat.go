package heartbeat

import (
	"agent/host"
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	zap.S().Info("health daemon startup")
	getAgentStat(time.Now())
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			{
				host.RefreshHost()
				getAgentStat(t)
				getPlgStat(t)
			}
		}
	}
}
