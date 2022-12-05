package heartbeat

import (
	"agent/host"
	"agent/plugin"
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

func Startup(ctx context.Context, p *plugin.Manager, wg *sync.WaitGroup) {
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
				getPlgStat(p, t)
			}
		}
	}
}
