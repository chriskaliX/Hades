package plugin

import (
	"agent/agent"
	"agent/transport"
	"context"
	"sync"

	"github.com/chriskaliX/SDK/transport/protocol"
	"go.uber.org/zap"
)

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			DefaultManager.UnregisterAll()
			return
		case cfgs := <-DefaultManager.syncCh:
			// 加载插件
			for _, cfg := range cfgs {
				if cfg.Name == agent.Product {
					continue
				}
				if err := DefaultManager.Load(ctx, *cfg); err != nil {
					zap.S().Error(err)
				} else {
					zap.S().Infof("plugin %s has been loaded", cfg.Name)
				}
			}
			// 移除插件
			for _, plg := range DefaultManager.GetAll() {
				if _, ok := cfgs[plg.Name()]; ok {
					continue
				}
				if err := DefaultManager.UnRegister(plg.Name()); err != nil {
					zap.S().Error(err)
				}
			}
		}
	}
}

func init() {
	go func() {
		for {
			select {
			case task := <-transport.PluginTaskChan:
				// In future, shutdown, update, restart will be in here
				if plg, ok := DefaultManager.Get(task.GetObjectName()); ok {
					if err := plg.SendTask((protocol.Task)(*task)); err != nil {
						zap.S().Error("send task to plugin: ", err)
					}
				} else {
					zap.S().Error("can't find plugin: ", task.GetObjectName())
				}
			case cfgs := <-transport.PluginConfigChan:
				if err := DefaultManager.Sync(cfgs); err != nil {
					zap.S().Error("config sync failed: ", err)
				}
			}
		}
	}()
}
